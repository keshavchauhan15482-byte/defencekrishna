from __future__ import annotations

import os
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


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_env() -> Path:
    py = venv_python()
    if not py.exists():
        print("[Krishna Defence] Creating local Python environment...")
        venv.EnvBuilder(with_pip=True).create(VENV)
    req = ROOT / "garuda_v3" / "requirements.txt"
    print("[Krishna Defence] Ensuring dependencies are installed...")
    subprocess.check_call([str(py), "-m", "pip", "install", "-r", str(req)])
    return py


def wait_and_open(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(URL, timeout=1.0):
                webbrowser.open(URL)
                print(f"[Krishna Defence] Opened {URL}")
                return
        except Exception:
            time.sleep(0.5)
    print(f"[Krishna Defence] Server started; open {URL} manually if the browser did not open.")


def main() -> int:
    os.chdir(ROOT)
    py = ensure_env()
    print("[Krishna Defence] Starting integrated Garuda V15 localhost demo...")
    proc = subprocess.Popen([str(py), "-m", "garuda_v3.integrated_server"], cwd=ROOT)
    try:
        wait_and_open()
        token_file = ROOT / "garuda_v3" / "runtime" / "access.json"
        print(f"[Krishna Defence] Viewer/operator tokens are generated locally at: {token_file}")
        print("[Krishna Defence] Keep this window open while using the dashboard. Press Ctrl+C to stop.")
        return proc.wait()
    except KeyboardInterrupt:
        print("\n[Krishna Defence] Stopping localhost demo...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
