#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Local experiment control. One JSON result on stdout, nonzero on failure."""
import argparse
import json
import socket
import sys


def request(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(5)
        client.connect(path)
        client.sendall(f"owlbear.control.v1 {command}".encode("ascii"))
        data, _, flags, _ = client.recvmsg(8192)
        if flags & socket.MSG_TRUNC:
            raise ValueError("truncated control reply")
        result = json.loads(data)
        if result.get("schema") != "owlbear.control.v1" or not isinstance(result.get("ok"), bool):
            raise ValueError("unsupported control reply")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("command", choices=("health", "flush", "reset", "stop"))
    args = parser.parse_args()
    try:
        result = request(args.socket, args.command)
    except (OSError, ValueError) as exc:
        result = {"schema": "owlbear.control.v1", "ok": False, "error": str(exc)}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
