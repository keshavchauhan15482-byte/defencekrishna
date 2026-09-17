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
ENGINE_URL = "http://127.0.0.1:8090"
CONSOLE_URL = "http://127.0.0.1:8091"
ENGINE_HEALTH_URL = ENGINE_URL + "/health"
CONSOLE_HEALTH_URL = CONSOLE_URL + "/health"
ENGINE_LOG = ROOT / "garuda_v3" / "runtime" / "localhost.log"
CONSOLE_LOG = ROOT / "garuda_v3" / "runtime" / "legacy_console.log"


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


def port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1.5) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def tail_log(path: Path, lines: int = 40) -> str:
    try:
        text = path.read_text(errors="replace").splitlines()
        return "\n".join(text[-lines:])
    except Exception:
        return "(no localhost log was written)"


def wait_until_ready(processes: list[subprocess.Popen], timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for proc in processes:
            code = proc.poll()
            if code is not None:
                print(f"[Krishna Defence] A localhost service exited during startup (code {code}).", flush=True)
                print("--- Garuda engine log ---", flush=True)
                print(tail_log(ENGINE_LOG), flush=True)
                print("--- Legacy console log ---", flush=True)
                print(tail_log(CONSOLE_LOG), flush=True)
                return False
        if http_ok(ENGINE_HEALTH_URL) and http_ok(ENGINE_URL) and http_ok(CONSOLE_HEALTH_URL) and http_ok(CONSOLE_URL):
            return True
        time.sleep(0.4)
    print("[Krishna Defence] Local services did not become healthy in time.", flush=True)
    print("--- Garuda engine log ---", flush=True)
    print(tail_log(ENGINE_LOG), flush=True)
    print("--- Legacy console log ---", flush=True)
    print(tail_log(CONSOLE_LOG), flush=True)
    return False


def start_services(py: Path) -> tuple[list[subprocess.Popen], list[object]]:
    ENGINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    engine_log = ENGINE_LOG.open("w")
    console_log = CONSOLE_LOG.open("w")
    engine = subprocess.Popen(
        [str(py), "-m", "garuda_v3.integrated_server"],
        cwd=ROOT,
        stdout=engine_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    console = subprocess.Popen(
        [str(py), "-m", "garuda_v3.legacy_console"],
        cwd=ROOT,
        stdout=console_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return [engine, console], [engine_log, console_log]


def stop_service(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch Garuda engine + integrated legacy Ultron console")
    parser.add_argument("--smoke", action="store_true", help="verify both localhost services and exit")
    parser.add_argument("--skip-install", action="store_true", help="do not install requirements")
    parser.add_argument("--current-python", action="store_true", help="use the current Python instead of .venv")
    parser.add_argument("--no-browser", action="store_true", help="do not open the default browser")
    args = parser.parse_args()

    os.chdir(ROOT)
    engine_open = port_is_open(8090)
    console_open = port_is_open(8091)
    if engine_open or console_open:
        if http_ok(ENGINE_HEALTH_URL) and http_ok(ENGINE_URL) and http_ok(CONSOLE_HEALTH_URL) and http_ok(CONSOLE_URL):
            print(f"[Krishna Defence] Garuda engine is running at {ENGINE_URL}", flush=True)
            print(f"[Krishna Defence] Integrated Ultron console is running at {CONSOLE_URL}", flush=True)
            if not args.smoke and not args.no_browser:
                webbrowser.open(CONSOLE_URL)
            return 0
        occupied = []
        if engine_open:
            occupied.append("8090")
        if console_open:
            occupied.append("8091")
        print("[Krishna Defence] Port(s) " + ", ".join(occupied) + " are already in use by an incomplete/other service. Stop them and retry.", flush=True)
        return 2

    try:
        py = ensure_env(use_current_python=args.current_python, skip_install=args.skip_install)
    except Exception as exc:
        print(f"[Krishna Defence] Setup failed: {exc}", flush=True)
        return 2

    print("[Krishna Defence] Starting Garuda V15 engine on 8090 + integrated Ultron console on 8091...", flush=True)
    processes, log_handles = start_services(py)
    try:
        if not wait_until_ready(processes):
            return 3
        print(f"[Krishna Defence] ENGINE HEALTHY: {ENGINE_URL}", flush=True)
        print(f"[Krishna Defence] ULTRON CONSOLE HEALTHY: {CONSOLE_URL}", flush=True)
        token_file = ROOT / "garuda_v3" / "runtime" / "access.json"
        print(f"[Krishna Defence] Local access tokens remain server-side: {token_file}", flush=True)
        if args.smoke:
            return 0
        if not args.no_browser:
            opened = webbrowser.open(CONSOLE_URL)
            if opened:
                print("[Krishna Defence] Browser launch requested for the integrated Ultron console.", flush=True)
            else:
                print(f"[Krishna Defence] Browser could not be opened automatically. Open {CONSOLE_URL} manually.", flush=True)
        print("[Krishna Defence] Keep this window open. Press Ctrl+C to stop both services.", flush=True)
        while all(proc.poll() is None for proc in processes):
            time.sleep(0.5)
        print("[Krishna Defence] A localhost service stopped unexpectedly.", flush=True)
        return 3
    except KeyboardInterrupt:
        print("\n[Krishna Defence] Stopping localhost services...", flush=True)
        return 0
    finally:
        for proc in processes:
            stop_service(proc)
        for handle in log_handles:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
