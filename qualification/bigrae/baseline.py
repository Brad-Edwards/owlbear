#!/usr/bin/env python3
"""Caller-owned baseline on a fresh benign target, before protection starts."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time


def wait_for_workload(process, info, timeout=10):
    """Wait for the game's complete newline-terminated discovery record."""
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        try:
            record = info.read_text()
        except FileNotFoundError:
            record = ""
        if record.endswith("\n"):
            fields = record.split()
            if len(fields) != 2 or int(fields[0]) != process.pid:
                raise RuntimeError("baseline workload identity mismatch")
            address = int(fields[1], 0)
            if address <= 0:
                raise RuntimeError("invalid baseline workload address")
            return address
        time.sleep(.05)
    raise RuntimeError("baseline workload did not become ready")


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
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pid_file = args.output.with_suffix(".target.pid")
    created_pid_file = False
    with (args.output.parent / "baseline-game.log").open("x") as log:
        process = subprocess.Popen([str(args.release / "game/owlbear-game"), "--no-curses"], stdout=log, stderr=log)
        try:
            address = wait_for_workload(process, info)
            if address <= 0:
                raise RuntimeError("invalid baseline workload address")
            descriptor = os.open(pid_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created_pid_file = True
            with os.fdopen(descriptor, "w") as stream:
                stream.write(str(process.pid) + "\n")
            # The checker must not gain a parent-of-target exception from Yama.
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("check-memory.py")),
                                     "--phase", "baseline", "--pid-file", str(pid_file),
                                     "--output", str(args.output)], timeout=20, check=False)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            if created_pid_file:
                pid_file.unlink()
    if info.exists() or info.is_symlink():
        raise RuntimeError("baseline workload did not remove its discovery file")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
