#!/usr/bin/env python3
"""Caller-owned baseline on a fresh benign target, before protection starts."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    info = Path("/tmp/owlbear-game.info")
    if os.geteuid() != 0 or info.exists() or info.is_symlink() or Path("/sys/module/owlbear").exists():
        parser.error("an unprotected disposable guest without stale workload state is required")
    if args.output.exists() or args.output.is_symlink():
        parser.error("baseline evidence already exists")
    spec = importlib.util.spec_from_file_location("memory_checks", Path(__file__).with_name("check-memory.py"))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (args.output.parent / "baseline-game.log").open("x") as log:
        process = subprocess.Popen([str(args.release / "game/owlbear-game"), "--no-curses"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while not info.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("baseline workload did not become ready")
                time.sleep(.05)
            fields = info.read_text().split()
            if int(fields[0]) != process.pid:
                raise RuntimeError("baseline workload identity mismatch")
            results = checks.check(process.pid, int(fields[1], 0))
            passed = checks.classify(results, "baseline")
            receipt = {"schema": "owlbear.qualification.memory/v1", "phase": "baseline",
                       "target_pid": process.pid, "results": results, "passed": passed}
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(receipt, stream, sort_keys=True)
                stream.write("\n")
            print(json.dumps(receipt, sort_keys=True))
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
    if info.exists() or info.is_symlink():
        raise RuntimeError("baseline workload did not remove its discovery file")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
