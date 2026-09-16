"""V44 exact live-runtime contract and fail-closed validators."""
from __future__ import annotations

from typing import Iterable
import numpy as np
import pandas as pd

from garuda_v3.data import FEATURES, MAX_NODES, SCHEMA

WINDOW_SECONDS = 10
HISTORY = 8
HORIZON = 4
EVIDENCE_SCOPE = "development_reused_holdout"
FORBIDDEN_FEATURE_TOKENS = (
    "process", "pid", "thread", "cpu", "memory", "disk", "system", "kernel",
    "user", "command", "temperature", "voltage", "current", "power", "sensor",
    "device", "filesystem", "handle", "label", "class", "attack", "alert",
)


def unix_seconds(values: Iterable) -> np.ndarray:
    """Convert datetime-like values to Unix seconds without assuming pandas' storage unit."""
    dt = pd.to_datetime(values, utc=True, errors="raise")
    epoch = pd.Timestamp("1970-01-01", tz="UTC")
    return ((dt - epoch) // pd.Timedelta(seconds=1)).to_numpy(dtype=np.int64)


def validate_feature_names(features: Iterable[str]) -> list[str]:
    names = list(features)
    errors = []
    if names != list(FEATURES):
        errors.append("feature_order_mismatch")
    bad = [name for name in names if any(token in name.casefold() for token in FORBIDDEN_FEATURE_TOKENS)]
    if bad:
        errors.append("forbidden_feature_names:" + ",".join(bad))
    return errors


def validate_metadata(metadata: dict, require_packet_features: bool = True) -> list[str]:
    errors = []
    if metadata.get("schema") != SCHEMA:
        errors.append(f"schema:{metadata.get('schema')!r}")
    errors.extend(validate_feature_names(metadata.get("features", [])))
    if int(metadata.get("window_seconds", -1)) != WINDOW_SECONDS:
        errors.append(f"window_seconds:{metadata.get('window_seconds')!r}")
    if int(metadata.get("max_nodes", -1)) != MAX_NODES:
        errors.append(f"max_nodes:{metadata.get('max_nodes')!r}")
    if metadata.get("synthetic") is not False:
        errors.append("synthetic_or_unspecified")
    if require_packet_features and metadata.get("packet_features") is not True:
        errors.append("packet_features_not_observed")
    return errors


def assert_runtime_dataset(dataset: dict, require_packet_features: bool = True) -> None:
    errors = validate_metadata(dataset.get("metadata", {}), require_packet_features)
    x = np.asarray(dataset.get("x"))
    adj = np.asarray(dataset.get("adj"))
    mask = np.asarray(dataset.get("mask"))
    times = np.asarray(dataset.get("times"))
    if x.ndim != 3 or x.shape[-1] != len(FEATURES) or x.shape[1] != MAX_NODES:
        errors.append(f"x_shape:{x.shape}")
    if adj.ndim != 3 or adj.shape[1:] != (MAX_NODES, MAX_NODES):
        errors.append(f"adj_shape:{adj.shape}")
    if mask.ndim != 2 or mask.shape[1] != MAX_NODES:
        errors.append(f"mask_shape:{mask.shape}")
    if not (len(x) == len(adj) == len(mask) == len(times)):
        errors.append("window_count_mismatch")
    if len(times) > 1 and np.any(np.diff(times) <= 0):
        errors.append("timestamps_not_strictly_increasing")
    if errors:
        raise ValueError("V44 runtime contract refused: " + "; ".join(errors))
