from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.request
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
URL = "http://127.0.0.1:8090"
HEALTH_URL = URL + "/health"
LOG = ROOT / "garuda_v3" / "runtime" / "localhost.log"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_env(*, use_current_python: bool = False, skip_install: bool = False) -> Path:
    if sys.version_info < (3, 10):
        raise RuntimeError(f"Python 3.10+ required; found {sys.version.split()[0]}")
    if use_current_python:
        py = Path(sys.executable)
    else:
        py = venv_python()
        if not py.exists():
            print("[Krishna Defence] Creating local Python environment...", flush=True)
            venv.EnvBuilder(with_pip=True).create(VENV)
    if not skip_install:
        req = ROOT / "garuda_v3" / "requirements.txt"
        print("[Krishna Defence] Installing/validating dependencies...", flush=True)
        subprocess.check_call([str(py), "-m", "pip", "install", "-r", str(req)])
    return py


def port_is_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", 8090)) == 0


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1.5) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def tail_log(lines: int = 40) -> str:
    try:
        text = LOG.read_text(errors="replace").splitlines()
        return "\n".join(text[-lines:])
    except Exception:
        return "(no localhost log was written)"


def wait_until_ready(proc: subprocess.Popen, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        code = proc.poll()
        if code is not None:
            print(f"[Krishna Defence] Server exited during startup (code {code}).", flush=True)
            print(tail_log(), flush=True)
            return False
        if http_ok(HEALTH_URL) and http_ok(URL):
            return True
        time.sleep(0.4)
    print("[Krishna Defence] Server did not become healthy in time.", flush=True)
    print(tail_log(), flush=True)
    return False


def start_server(py: Path) -> tuple[subprocess.Popen, object]:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    log_handle = LOG.open("w")
    proc = subprocess.Popen(
        [str(py), "-m", "garuda_v3.integrated_server"],
        cwd=ROOT,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc, log_handle


def stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the integrated Krishna Defence + Garuda V15 localhost demo")
    parser.add_argument("--smoke", action="store_true", help="verify localhost startup and exit")
    parser.add_argument("--skip-install", action="store_true", help="do not install requirements")
    parser.add_argument("--current-python", action="store_true", help="use the current Python instead of .venv")
    parser.add_argument("--no-browser", action="store_true", help="do not open the default browser")
    args = parser.parse_args()

    os.chdir(ROOT)
    if port_is_open():
        if http_ok(HEALTH_URL) and http_ok(URL):
            print(f"[Krishna Defence] Demo is already running at {URL}", flush=True)
            if not args.smoke and not args.no_browser:
                webbrowser.open(URL)
            return 0
        print("[Krishna Defence] Port 8090 is already used by another process. Stop it and retry.", flush=True)
        return 2

    try:
        py = ensure_env(use_current_python=args.current_python, skip_install=args.skip_install)
    except Exception as exc:
        print(f"[Krishna Defence] Setup failed: {exc}", flush=True)
        return 2

    print("[Krishna Defence] Starting integrated Garuda V15 localhost demo...", flush=True)
    proc, log_handle = start_server(py)
    try:
        if not wait_until_ready(proc):
            return 3
        print(f"[Krishna Defence] HEALTHY: {URL}", flush=True)
        token_file = ROOT / "garuda_v3" / "runtime" / "access.json"
        print(f"[Krishna Defence] Local access tokens: {token_file}", flush=True)
        if args.smoke:
            return 0
        if not args.no_browser:
            opened = webbrowser.open(URL)
            if opened:
                print("[Krishna Defence] Browser launch requested.", flush=True)
            else:
                print(f"[Krishna Defence] Browser could not be opened automatically. Open {URL} manually.", flush=True)
        print("[Krishna Defence] Keep this window open. Press Ctrl+C to stop.", flush=True)
        return proc.wait()
    except KeyboardInterrupt:
        print("\n[Krishna Defence] Stopping localhost demo...", flush=True)
        return 0
    finally:
        stop_server(proc)
        log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
