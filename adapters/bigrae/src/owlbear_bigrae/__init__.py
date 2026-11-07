"""Independent BigRAE runtime adapter; no platform or provider imports."""
import argparse
import base64
from importlib.resources import files
import json
from pathlib import PurePosixPath
import re

from bigrae_adapter_sdk.runtime import GuestAction, PluginManifest, RuntimePlan, decode_message

PARAMETERS = ["configuration"]
VERSION = "0.2.0"


def configuration(raw):
    value = decode_message(raw, limit=8192)
    keys = {"release", "manifest_sha256", "build_id", "version", "source_commit",
            "kernel_release", "target_pid", "sensors", "enforce"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("configuration keys must exactly match the adapter contract")
    for key in ("manifest_sha256", "build_id"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise ValueError("exact SHA-256 identities required")
    patterns = {"release": r"/opt/owlbear/releases/[a-zA-Z0-9._-]+",
                "version": r"[0-9]+\.[0-9]+\.[0-9]+", "source_commit": r"[a-f0-9]{40}",
                "kernel_release": r"[a-zA-Z0-9._+-]{1,128}"}
    for key, pattern in patterns.items():
        if not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]):
            raise ValueError("invalid release identity")
    if value["release"].rsplit("/", 1)[-1] in {".", ".."}:
        raise ValueError("invalid release path")
    target = value["target_pid"]
    if type(target) is int:
        if not 1 < target <= 2147483647:
            raise ValueError("target must be an explicit process PID")
    elif (not isinstance(target, str) or not re.fullmatch(r"/run/[a-zA-Z0-9._/-]{1,240}\.pid", target)
          or str(PurePosixPath(target)) != target or any(part in (".", "..") for part in target.split("/"))):
        raise ValueError("target must be a process PID or canonical /run PID file")
    if type(value["enforce"]) is not bool:
        raise ValueError("enforce must be boolean")
    sensors = value["sensors"]
    if (not isinstance(sensors, list) or any(s not in ("lsm", "trace", "kprobe", "net") for s in sensors)
            or len(sensors) != len(set(sensors))):
        raise ValueError("invalid sensor selection")
    return value


def manifest(worker_image):
    return PluginManifest(protocol="bigrae.runtime-plugin/v1", plugin_id="owlbear",
                          version=VERSION, distribution="owlbear-bigrae-adapter", entry_point="owlbear",
                          worker_image=worker_image, capabilities=["guest.configure", "guest.verify"],
                          required_bindings=["guest"], required_parameters=PARAMETERS)


class Plugin:
    def plan(self, request):
        try:
            expected = manifest(request.manifest.worker_image)
            if request.manifest != expected or request.targets["guest"].os_family != "linux":
                raise ValueError("unsupported installed declaration or guest")
            config = configuration(request.parameters["configuration"])
            actions = []
            if request.phase in ("configure", "verify"):
                payload = dict(configuration=config, phase=request.phase, operation=str(request.operation_id))
                data = base64.b64encode(json.dumps(payload).encode()).decode()
                source = files(__package__).joinpath("guest.py").read_text()
                script = "python3 - <<'OWLB_GUEST'\n" + source + f"\nrun('{data}')\nOWLB_GUEST\n"
                actions = [GuestAction(action_id="owlbear-" + request.phase, binding="guest",
                                       script=script, timeout_seconds=120)]
            # Core destroys the guest; cleanup must not stop another operation's process.
            result = RuntimePlan(protocol=request.protocol, invocation_id=request.invocation_id,
                                 input_digest=request.digest, phase=request.phase, status="planned", actions=actions)
            result.authorize(request)
            return result
        except (ValueError, KeyError, TypeError):
            return RuntimePlan(protocol=request.protocol, invocation_id=request.invocation_id,
                               input_digest=request.digest, phase=request.phase, status="failed",
                               failure_code="invalid-input")


def factory():
    return Plugin()


def main():
    parser = argparse.ArgumentParser(description="Emit the exact BigRAE installation manifest")
    parser.add_argument("--worker-image", required=True, help="registry image@sha256:digest")
    args = parser.parse_args()
    print(manifest(args.worker_image).model_dump_json(indent=2))
