from __future__ import annotations

import subprocess
import time
import urllib.request
import webbrowser
from pathlib import Path

import start_local

ROOT = Path(__file__).resolve().parent
ENGINE_URL = "http://127.0.0.1:8090"
CONSOLE_URL = "http://127.0.0.1:8091/console.html"
EXPECTED_BUILD = "v132-nationals-console"


def console_is_current() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8091/health", timeout=1.5) as response:
            import json
            data = json.loads(response.read().decode("utf-8"))
            return data.get("console_build") == EXPECTED_BUILD and data.get("surface") == "console.html"
    except Exception:
        return False


def main() -> int:
    if start_local.port_is_open(8090) or start_local.port_is_open(8091):
        if console_is_current() and start_local.http_ok(ENGINE_URL + "/health"):
            print(f"[Krishna Defence] MAIN console already running: {CONSOLE_URL}", flush=True)
            webbrowser.open(CONSOLE_URL + "?build=" + EXPECTED_BUILD)
            return 0
        print("[Krishna Defence] An older/different localhost service is using 8090/8091.", flush=True)
        print("[Krishna Defence] Stop the old terminal/server first, then run START_LOCAL.command again.", flush=True)
        return 2

    py = start_local.ensure_env()
    runtime = ROOT / "garuda_v3" / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    engine_log = (runtime / "localhost.log").open("w")
    console_log = (runtime / "main_console.log").open("w")
    engine = subprocess.Popen([str(py), "-m", "garuda_v3.integrated_server"], cwd=ROOT, stdout=engine_log, stderr=subprocess.STDOUT, text=True)
    console = subprocess.Popen([str(py), "-m", "garuda_v3.main_console"], cwd=ROOT, stdout=console_log, stderr=subprocess.STDOUT, text=True)
    processes = [engine, console]
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            if any(p.poll() is not None for p in processes):
                print("[Krishna Defence] A localhost service exited during startup.", flush=True)
                return 3
            if start_local.http_ok(ENGINE_URL + "/health") and console_is_current():
                print(f"[Krishna Defence] MAIN console.html healthy: {CONSOLE_URL}", flush=True)
                print(f"[Krishna Defence] Build identity: {EXPECTED_BUILD}", flush=True)
                webbrowser.open(CONSOLE_URL + "?build=" + EXPECTED_BUILD)
                print("[Krishna Defence] Keep this terminal open. Press Ctrl+C to stop.", flush=True)
                while all(p.poll() is None for p in processes):
                    time.sleep(0.5)
                return 3
            time.sleep(0.4)
        print("[Krishna Defence] Main console did not become healthy in time.", flush=True)
        return 3
    except KeyboardInterrupt:
        print("\n[Krishna Defence] Stopping local services...", flush=True)
        return 0
    finally:
        for p in processes:
            start_local.stop_service(p)
        engine_log.close()
        console_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
