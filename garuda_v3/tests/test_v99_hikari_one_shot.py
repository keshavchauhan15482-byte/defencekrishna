import hashlib
from pathlib import Path

import numpy as np

from garuda_v3.data import FEATURES
from garuda_v3.v99_hikari_one_shot import (
    HISTORY,
    HORIZON,
    WINDOW_SECONDS,
    _flow_from_packets,
    build_sequences,
    git_blob_sha1,
)


def test_git_blob_sha1_matches_git_object_formula(tmp_path):
    path = tmp_path / "blob.bin"
    raw = b"garuda-v99"
    path.write_bytes(raw)
    expected = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    assert git_blob_sha1(path) == expected


def test_build_sequences_preserves_frozen_history_horizon_contract():
    windows = HISTORY + HORIZON + 2
    times = np.arange(windows, dtype=np.int64) * WINDOW_SECONDS
    x = np.zeros((windows, 32, len(FEATURES)), dtype=np.float32)
    adj = np.zeros((windows, 32, 32), dtype=np.float32)
    mask = np.zeros((windows, 32), dtype=np.float32)
    mask[:, 0] = 1
    for i in range(windows):
        x[i, 0, 0] = i / 100.0
    sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    assert sx.shape[1:] == (HISTORY, 32, len(FEATURES))
    assert sa.shape[1:] == (HISTORY, 32, 32)
    assert sm.shape[1:] == (HISTORY, 32)
    assert target.shape[1:] == (HORIZON, len(FEATURES))
    assert len(cutoffs) == windows - (HISTORY + HORIZON) + 1
    np.testing.assert_allclose(target[0, :, 0], np.arange(HISTORY, HISTORY + HORIZON) / 100.0)


def test_build_sequences_never_gap_fills():
    windows = HISTORY + HORIZON
    times = np.arange(windows, dtype=np.int64) * WINDOW_SECONDS
    times[HISTORY] += WINDOW_SECONDS
    x = np.zeros((windows, 32, len(FEATURES)), dtype=np.float32)
    adj = np.zeros((windows, 32, 32), dtype=np.float32)
    mask = np.ones((windows, 32), dtype=np.float32)
    try:
        build_sequences(times, x, adj, mask)
    except RuntimeError as exc:
        assert "no contiguous" in str(exc)
    else:
        raise AssertionError("gapped timelines must not be converted into synthetic contiguous sequences")


def test_packet_flow_adapter_derives_retransmission_fraction():
    base = {
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 12345,
        "dport": 443,
        "protocol": "tcp",
        "bytes": 100,
        "ttl": 64,
        "frag": False,
        "flags": 0x18,
        "win": 4096,
        "payload_len": 10,
    }
    packets = [
        dict(base, t=1.0, seq=100),
        dict(base, t=1.1, seq=100),
        dict(base, t=1.2, seq=110),
    ]
    flow = _flow_from_packets(packets)
    assert flow["retransmission_count"] == 1
    assert np.isclose(flow["retransmission_fraction"], 1 / 3)
    assert flow["packet_present"] is True


def test_active_feature_contract_contains_packet_provenance_channel():
    assert "packet_features_present" in FEATURES
    assert "ttl_mean_scaled" in FEATURES
    assert "ttl_variance_scaled" in FEATURES
    assert "fragment_fraction" in FEATURES
    assert "duplicate_payload_segment_fraction" in FEATURES
