"""Bounded, explicit tcpdump collection on an owned interface.

This optional source creates immutable closed captures for live_publisher. Each
capture is standalone and at least 90s long (80s history plus future windows).
The cadence is capture-duration, NOT packet-by-packet or a 10s streaming IDS.
Requires an existing tcpdump installation and OS capture permissions.
"""
from __future__ import annotations

import argparse
import os
import secrets
import shutil
import signal
import subprocess
import time
from pathlib import Path


def capture_once(interface, inbox, seconds=90):
    if not interface or interface.startswith("-") or len(interface) > 80:
        raise ValueError("Explicit physical/virtual interface name required")
    if not 90 <= seconds <= 600:
        raise ValueError("Capture duration must be 90..600 seconds")
    binary = shutil.which("tcpdump")
    if not binary:
        raise RuntimeError("tcpdump is not installed or unavailable in PATH")
    folder = Path(inbox).resolve()
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Capture inbox must exist and not be a symlink")
    temporary = folder / ("pending-" + secrets.token_hex(12) + ".pcap")
    completed = folder / ("capture-" + secrets.token_hex(12) + ".pcap.ready")
    if temporary.exists() or completed.exists():
        raise ValueError("Capture path collision")
    try:
        # Never execute through a shell; do not allow website-supplied targets.
        proc = subprocess.Popen(
            [binary, "-i", interface, "-s", "0", "-w", str(temporary)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                raise RuntimeError("tcpdump failed to stop cleanly")
        if proc.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT):
            raise RuntimeError("tcpdump exited abnormally")
        if not temporary.is_file() or temporary.stat().st_size <= 24:
            raise RuntimeError("Capture was empty or not created")
        os.chmod(temporary, 0o600)
        os.replace(temporary, completed)
        return completed
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, help="Your authorized local capture interface")
    parser.add_argument("--inbox", required=True)
    parser.add_argument("--capture-seconds", type=int, default=90)
    parser.add_argument("--repeat", action="store_true", help="Continue taking 90+ second captures")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you own or have permission to monitor this network")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("Explicit --authorized acknowledgement required")
    while True:
        complete = capture_once(args.interface, args.inbox, args.capture_seconds)
        print("Completed local capture:", complete.name, flush=True)
        if not args.repeat:
            break


if __name__ == "__main__":
    main()
