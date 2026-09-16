"""Regression tests for the V44 strict network-only feature gate."""
import importlib.util
from pathlib import Path
import pandas as pd

SRC = Path(__file__).resolve().parent / "v15_xiiotid_pilot_v2.py"
spec = importlib.util.spec_from_file_location("v15_gate", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_system_fields_are_rejected():
    df = pd.DataFrame({
        "Flow Duration": range(10),
        "Total Fwd Packets": range(10, 20),
        "TCP Window": range(20, 30),
        "CPU Usage": range(30, 40),
        "Process PID": range(40, 50),
        "Memory Utilization": range(50, 60),
    })
    selected = mod.choose_numeric_features(df, set())
    assert "CPU Usage" not in selected
    assert "Process PID" not in selected
    assert "Memory Utilization" not in selected
    assert "Flow Duration" in selected
    assert "Total Fwd Packets" in selected
    assert "TCP Window" in selected


def test_insufficient_network_schema_fails_closed():
    df = pd.DataFrame({
        "CPU Usage": range(10),
        "Memory Utilization": range(10, 20),
        "Process PID": range(20, 30),
    })
    try:
        mod.choose_numeric_features(df, set())
    except RuntimeError as exc:
        assert "network-only" in str(exc)
    else:
        raise AssertionError("mixed system telemetry must not be accepted")


if __name__ == "__main__":
    test_system_fields_are_rejected()
    test_insufficient_network_schema_fails_closed()
    print("V44 strict network-only tests: PASS")
