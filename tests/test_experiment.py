# SPDX-License-Identifier: GPL-2.0-only
"""Local integration tests; real processes/files, explicit fake kernel/BPF fixture."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ctl", ROOT / "scripts/owlbearctl.py")
ctl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctl)


class ExperimentIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build.name) / "owlbeard"
        sources = ["main", "experiment", "event_pipeline", "process_tree", "sig_loader",
                   "integrity", "hmac_sha256", "self_protect", "debugger_detect",
                   "preload_detect", "clock_validator", "vdso_integrity", "policy",
                   "scanner", "net_allowlist"]
        # Optional source substitution supports deliberate mutation checks.
        override = os.environ.get("OWL_MUTANT_SOURCE")
        inputs = [str(Path(override) if override and name == "experiment" else
                      ROOT / "daemon" / f"{name}.c") for name in sources]
        subprocess.run(["gcc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(ROOT / "include"), "-I" + str(ROOT / "daemon"),
                        *inputs, str(ROOT / "tests/experiment_fixture.c"),
                        "-lcrypto", "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = Path(self.tmp.name)
        self.path = str(self.run_dir / "control.sock")
        os.mkfifo(self.run_dir / "device", 0o600)
        self.device = os.open(self.run_dir / "device", os.O_RDWR | os.O_NONBLOCK)
        self.addCleanup(os.close, self.device)
        self.proc = None

    def start(self, sensors="none", enforce=False, fsync_fail=False):
        args = [str(self.binary), "--target", str(os.getpid()), "--sensors", sensors,
                "--device", str(self.run_dir / "device"), "--control", self.path,
                "--events", str(self.run_dir / "events.jsonl"),
                "--sigs", str(ROOT / "signatures/default.sigs")]
        if enforce:
            args.append("--enforce")
        env = dict(os.environ)
        if fsync_fail:
            env["OWL_TEST_FSYNC_FAIL"] = "1"
        self.proc = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup_process)
        for _ in range(60):
            if self.proc.poll() is not None:
                self.fail(f"daemon exited: {self.proc.returncode}")
            try:
                return ctl.request(self.path, "health")
            except OSError:
                time.sleep(.05)
        self.fail("socket not ready")

    def cleanup_process(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)

    def test_lifecycle_reset_and_durable_events(self):
        state = self.start(enforce=True)
        self.assertTrue(state["ready"])
        self.assertTrue(state["kernel_enforce"])
        self.assertTrue(state["evidence_loss_known"])
        self.assertEqual(state["attached_bpf"], 0)
        # Real 128-byte event, with arbitrary non-UTF8 process bytes.
        event = struct.pack("=Q6I16sQQ64s", 123456789, 0x101, 1, 0, 4321,
                            os.getpid(), 7, b'"\\\xff', 0, 0, bytes(range(64)))
        os.write(self.device, event)
        flushed = ctl.request(self.path, "flush")
        self.assertTrue(flushed["ok"])
        lines = (self.run_dir / "events.jsonl").read_text().splitlines()
        record = next(json.loads(line) for line in lines if json.loads(line)["sequence"] == 7)
        self.assertEqual(record["schema"], "owlbear.event.v1")
        self.assertEqual(record["timestamp_ns"], 123456789)
        self.assertEqual(bytes.fromhex(record["payload_hex"]), bytes(range(64)))
        self.assertEqual(bytes.fromhex(record["comm_hex"])[:3], b'"\\\xff')
        reset = ctl.request(self.path, "reset")
        self.assertTrue(reset["ok"])
        self.assertEqual(reset["epoch"], 1)
        self.assertEqual(reset["events_processed"], 0)
        self.assertEqual(reset["kernel_dropped"], flushed["kernel_dropped"])
        self.assertTrue(reset["kernel_enforce"])
        self.assertTrue(ctl.request(self.path, "stop")["ok"])
        self.assertEqual(self.proc.wait(timeout=5), 0)
        self.assertFalse(Path(self.path).exists())
        self.assertEqual((self.run_dir / "events.jsonl").stat().st_mode & 0o777, 0o600)

    def test_missing_sensors_are_not_ready(self):
        state = self.start("lsm,trace")
        self.assertFalse(state["ready"])
        self.assertEqual(state["requested_bpf"], 3)
        self.assertEqual(state["attached_bpf"], 0)
        self.assertFalse(state["requested_enforce"])
        self.assertIsNone(state["lsm_enforce"])

    def test_reject_unknown_protocol_and_command(self):
        self.start()
        for packet in (b"owlbear.control.v2 health", b"owlbear.control.v1 bogus",
                       b"x" * 100, b"owlbear.control.v1 health\0injected"):
            with self.subTest(packet=packet), socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
                sock.settimeout(5)
                sock.connect(self.path)
                sock.sendall(packet)
                self.assertFalse(json.loads(sock.recv(8192))["ok"])

    def test_reject_invalid_sensor_selection(self):
        for sensors in ("unknown", "lsm,", "lsm,lsm", "", "none,lsm"):
            with self.subTest(sensors=sensors):
                proc = subprocess.run([str(self.binary), "--target", str(os.getpid()),
                                       "--sensors", sensors], capture_output=True, timeout=5)
                self.assertNotEqual(proc.returncode, 0)

    def test_evidence_file_is_never_overwritten(self):
        path = self.run_dir / "events.jsonl"
        path.write_text("existing evidence")
        proc = subprocess.run([str(self.binary), "--target", str(os.getpid()),
                               "--events", str(path)], capture_output=True, timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(path.read_text(), "existing evidence")

    def test_failed_flush_and_stop_are_not_acknowledged(self):
        self.start(fsync_fail=True)
        self.assertFalse(ctl.request(self.path, "flush")["ok"])
        self.assertFalse(ctl.request(self.path, "stop")["ok"])
        self.assertIsNone(self.proc.poll())

    def test_private_control_directory_required(self):
        self.run_dir.chmod(0o755)
        proc = subprocess.run([str(self.binary), "--target", str(os.getpid()),
                               "--control", self.path, "--events",
                               str(self.run_dir / "events.jsonl")], capture_output=True, timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(Path(self.path).exists())
