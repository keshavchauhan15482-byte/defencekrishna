"""V44 strict selector for tabular network-only research inputs.

This module is versioned separately from V15 so archived V15 evidence remains immutable.
The live V44 checkpoint path uses canonical packet graph features from garuda_v3.data.
"""
from __future__ import annotations
import math
import numpy as np
import pandas as pd

NETWORK_WORDS = (
    "flow", "packet", "byte", "length", "protocol", "tcp", "udp", "icmp", "port",
    "flag", "syn", "ack", "rst", "fin", "psh", "urg", "ttl", "window", "payload",
    "iat", "interarrival", "duration", "rate", "fwd", "bwd", "forward", "backward",
    "header", "segment", "subflow", "connection", "count", "size", "active", "bulk",
    "downup", "initwin", "idle",
)
NON_NETWORK_WORDS = (
    "process", "pid", "thread", "cpu", "memory", "disk", "system", "kernel", "user",
    "command", "temperature", "voltage", "current", "power", "sensor", "os", "device",
    "service", "uptime", "loadavg", "filesystem", "handle", "privileged", "login",
)
LEAK_WORDS = (
    "label", "class", "attack", "alert", "rule", "ossec", "anomaly", "uid",
    "date", "timestamp", "time", "srcip", "scri", "desip", "dstip", "sourceip",
    "destinationip",
)


def norm(value) -> str:
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def choose_numeric_features(df: pd.DataFrame, excluded=(), minimum: int = 4, limit: int = 24) -> list[str]:
    """Return only usable network/packet columns; never fall back to mixed telemetry."""
    excluded = set(excluded)
    sample = df.head(min(len(df), 60_000))
    scored = []
    for column in df.columns:
        name = norm(column)
        if column in excluded or any(word in name for word in LEAK_WORDS):
            continue
        if any(word in name for word in NON_NETWORK_WORDS):
            continue
        if not any(word in name for word in NETWORK_WORDS):
            continue
        sx = sample[column].replace(["-", "?", "None", "none", "null", ""], np.nan)
        numeric = pd.to_numeric(sx, errors="coerce")
        coverage = float(numeric.notna().mean())
        if coverage < 0.85 or numeric.nunique(dropna=True) <= 1:
            continue
        variance = float(np.nanvar(numeric.to_numpy(dtype=float)))
        score = math.log1p(variance) if np.isfinite(variance) and variance >= 0 else -1
        scored.append((coverage, score, column))
    scored.sort(reverse=True)
    selected = [column for _, _, column in scored[:limit]]
    if len(selected) < minimum:
        raise RuntimeError(
            f"Strict network-only feature audit found {len(selected)} usable flow/packet columns; "
            f"minimum is {minimum}; refusing mixed-feature fallback"
        )
    return selected
