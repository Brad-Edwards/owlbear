#!/usr/bin/env python3
"""Measure memory-access syscall outcomes independently of Owlbear event logs."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import stat


class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def classify(results, phase):
    required = {"process_vm_readv", "process_vm_writev", "proc_mem", "ptrace"}
    if set(results) != required:
        return False
    if phase == "baseline":
        return all(item["return"] == item["expected_bytes"] and item["errno"] == 0 for item in results.values())
    return all(item["return"] == -1 and item["errno"] == errno.EPERM for item in results.values())


def check(pid, address):
    libc = ctypes.CDLL(None, use_errno=True)
    for name in ("process_vm_readv", "process_vm_writev"):
        function = getattr(libc, name)
        function.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong,
                             ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
        function.restype = ctypes.c_ssize_t
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    results = {}
    buffer = ctypes.c_uint32()
    local = IOVec(ctypes.addressof(buffer), ctypes.sizeof(buffer))
    remote = IOVec(address, ctypes.sizeof(buffer))
    for name in ("process_vm_readv", "process_vm_writev"):
        if name == "process_vm_writev":
            # Write only the health field, never code or an arbitrary address.
            buffer.value = 9999
            remote.base = address + 8
        ctypes.set_errno(0)
        returned = getattr(libc, name)(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        results[name] = {"return": returned, "errno": ctypes.get_errno(), "expected_bytes": 4}
    try:
        descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
        try:
            data = os.pread(descriptor, 4, address)
            results["proc_mem"] = {"return": len(data), "errno": 0, "expected_bytes": 4}
        finally:
            os.close(descriptor)
    except OSError as error:
        results["proc_mem"] = {"return": -1, "errno": error.errno, "expected_bytes": 4}
    ctypes.set_errno(0)
    returned = libc.ptrace(16, pid, None, None)  # PTRACE_ATTACH
    results["ptrace"] = {"return": returned, "errno": ctypes.get_errno(), "expected_bytes": 0}
    if returned == 0:
        try:
            os.waitpid(pid, 0)
        finally:
            if libc.ptrace(17, pid, None, None) != 0:  # PTRACE_DETACH
                raise RuntimeError("cannot detach the qualification tracer")
    return results


def target(info_path, pid_path):
    for path in (info_path, pid_path):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("caller-owned regular target files are required")
    pid = int(pid_path.read_text())
    fields = info_path.read_text().split()
    if len(fields) < 2 or int(fields[0]) != pid or pid <= 1:
        raise ValueError("target PID and workload information disagree")
    return pid, int(fields[1], 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("baseline", "protected"), required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--info", type=Path, default=Path("/tmp/owlbear-game.info"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required for comparable guest privileges")
    pid, address = target(args.info, args.pid_file)
    results = check(pid, address)
    passed = classify(results, args.phase)
    receipt = {"schema": "owlbear.qualification.memory/v1", "phase": args.phase,
               "target_pid": pid, "results": results, "passed": passed}
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
