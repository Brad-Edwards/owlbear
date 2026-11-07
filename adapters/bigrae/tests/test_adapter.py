"""Installed-wheel tests; subprocess worker tests are local integration tests."""
import json
import os
from pathlib import Path
import subprocess
import socket
import struct
import threading
import sys
import tempfile
import unittest
from uuid import uuid4

from bigrae_adapter_sdk.runtime import RuntimeInput, parse_input, parse_result
from owlbear_bigrae import configuration, factory, manifest
from owlbear_bigrae.guest import verify_health, module_note_id, health, bind_target, target_identity

IMAGE = "registry.example.org/owlbear/worker@sha256:" + "a" * 64
CONFIG = dict(release="/opt/owlbear/releases/release-1", manifest_sha256="b" * 64,
              build_id="c" * 64, source_commit="d" * 40, version="2.5.0",
              kernel_release="6.17.0-test", target_pid=123, sensors=["lsm", "trace"], enforce=True)


def request(phase="verify"):
    return RuntimeInput(protocol="bigrae.runtime-plugin/v1", invocation_id=uuid4(), operation_id=uuid4(),
                        pack_digest="sha256:" + "e" * 64, manifest=manifest(IMAGE), phase=phase,
                        provider="aws", range_id=1, targets={"guest": {"node_address": "nodes.guest", "os_family": "linux"}},
                        parameters={"configuration": json.dumps(CONFIG)})


def ready():
    return dict(schema="owlbear.control.v1", ok=True, ready=True, kernel_responsive=True,
                bpf_configured=True, bpf_delivery=True, code_integrity_baseline=True,
                vdso_baseline=True, signatures_loaded=True, output_failed=False,
                target_pid=123, kernel_target_pid=123, attached_bpf=3, requested_bpf=3,
                kernel_enforce=True, requested_enforce=True, lsm_enforce=True,
                kernel_dropped=0, bpf_dropped=None, evidence_loss_known=False, pid=999)


class AdapterTests(unittest.TestCase):
    def test_caller_pid_file_is_a_closed_configuration_choice(self):
        config = dict(CONFIG, target_pid="/run/owlbear-qualification/target.pid")
        self.assertEqual(configuration(json.dumps(config)), config)
        for path in ("/tmp/target.pid", "/run/../tmp/target.pid", "/run/./target.pid",
                     "/run//target.pid", "/run/target", "/run/target.pid\n"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                configuration(json.dumps(dict(CONFIG, target_pid=path)))

    def test_target_binding_rejects_changed_process_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid = os.getpid()
            original = bind_target(root, pid, True)
            self.assertEqual(bind_target(root, pid, False), original)
            self.assertEqual(original, target_identity(pid))
            changed = dict(original, start_time_ticks=original["start_time_ticks"] + 1)
            (root / "target.json").write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                bind_target(root, pid, True)
            with self.assertRaises(ValueError):
                bind_target(root, pid, False)

    def test_plans_bind_to_request_and_only_declared_guest(self):
        for phase in ("validate", "configure", "verify", "cleanup"):
            with self.subTest(phase=phase):
                original = request(phase)
                result = factory().plan(original)
                result.authorize(original)
                self.assertEqual(result.status, "planned")
                self.assertEqual(len(result.actions), int(phase in ("configure", "verify")))
                if result.actions:
                    self.assertEqual(result.actions[0].binding, "guest")
                    self.assertLessEqual(result.actions[0].timeout_seconds, 120)
                    self.assertIn("owlbear.control.v1 health", result.actions[0].script)
                replay = request(phase)
                with self.assertRaises(ValueError):
                    parse_result(result.model_dump_json(), replay)

    def test_configuration_rejects_unsafe_and_ambiguous_values(self):
        cases = [("release", "/opt/owlbear/releases/.."), ("release", "/tmp/release;id"),
                 ("release", "/opt/owlbear/releases/../other"), ("enforce", "true"),
                 ("manifest_sha256", "latest"), ("target_pid", True), ("target_pid", 1),
                 ("sensors", ["all"]), ("sensors", ["lsm", "lsm"]), ("sensors", [None])]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                config = dict(CONFIG, **{key: value})
                with self.assertRaises(ValueError):
                    configuration(json.dumps(config))
        with self.assertRaises(ValueError):
            configuration(json.dumps(dict(CONFIG, cloud_password="forbidden")))
        with self.assertRaises(ValueError):
            configuration(json.dumps(CONFIG)[:-1] + ',"enforce":false}')

    def test_health_readback_and_negative_conditions(self):
        self.assertEqual(verify_health(ready(), CONFIG), ready())
        for key, value in [("ready", False), ("attached_bpf", 1), ("requested_bpf", 15),
                           ("kernel_enforce", False), ("lsm_enforce", False), ("target_pid", 456),
                           ("kernel_target_pid", 456), ("schema", "other"), ("output_failed", True),
                           ("kernel_dropped", 1), ("kernel_dropped", False), ("code_integrity_baseline", False)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    verify_health(dict(ready(), **{key: value}), CONFIG)
        observe = dict(CONFIG, enforce=False, sensors=[])
        state = dict(ready(), requested_bpf=0, attached_bpf=0, kernel_enforce=False,
                     requested_enforce=False, lsm_enforce=None)
        verify_health(state, observe)

    def test_wrong_declarations_fail_without_actions(self):
        for os_family, version in [("windows", "0.1.0"), ("linux", "9.0.0")]:
            data = request().model_dump(mode="json")
            data["targets"]["guest"]["os_family"] = os_family
            data["manifest"]["version"] = version
            result = factory().plan(RuntimeInput.model_validate(data))
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.actions, [])

    def test_worker_from_installed_packages_outside_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            for phase in ("inspect", "validate", "configure", "verify"):
                data = request("verify").model_dump(mode="json")
                if phase == "inspect":
                    data = {key: data[key] for key in ("protocol", "invocation_id", "manifest")}
                data["phase"] = phase
                original = parse_input(json.dumps(data))
                environment = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "SHIFTER_PLUGIN_INPUT")}
                environment["BIGRAE_PLUGIN_INPUT"] = original.model_dump_json()
                proc = subprocess.run([sys.executable, "-I", "-m", "bigrae_adapter_sdk.worker"],
                                      env=environment, cwd=tmp, capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                result = parse_result(proc.stdout, original)
                self.assertEqual(result.status, "compatible" if phase == "inspect" else "planned")

    def test_worker_image_requires_exact_registry_digest(self):
        for image in ("registry.example.org/owlbear/worker:latest", "sha256:" + "a" * 64):
            with self.assertRaises(ValueError):
                manifest(image)

    def test_loaded_module_note_preserves_exact_identity(self):
        note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + bytes(range(20))
        self.assertEqual(module_note_id(note), bytes(range(20)).hex())
        for bad in (note[:-1], note.replace(b"GNU", b"BAD"), b"", struct.pack("<III", 4, 0, 3) + b"GNU\0"):
            with self.subTest(note=bad), self.assertRaises((ValueError, struct.error)):
                module_note_id(bad)

    def test_health_socket_integration_and_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = tmp + "/control.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
                server.bind(path)
                server.listen(2)
                server.settimeout(3)
                received = []
                def serve():
                    for reply in (json.dumps(ready()).encode(), b"x" * 9000):
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(3)
                            received.append(connection.recv(100))
                            connection.sendall(reply)
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                self.assertEqual(health(path), ready())
                with self.assertRaises(ValueError):
                    health(path)
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(received, [b"owlbear.control.v1 health"] * 2)
