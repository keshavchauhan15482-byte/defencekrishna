import struct
from pathlib import Path

import numpy as np
import pytest

from garuda_v3.data import FEATURES
from garuda_v3.v102_mawi_one_shot import (
    EXPECTED_CAPTURE,
    EXPECTED_MODEL_SHA256,
    EXPECTED_RECORDS,
    EXPECTED_SNAPLEN,
    EXPECTED_SUPPORT_SHA256,
    HORIZON,
    HISTORY,
    V102ContractError,
    _decode_truncated_ipv4,
    build_sequences,
)


def _ethernet_ipv4_tcp_frame(*, ip_total_len=200, captured_len=96):
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    version_ihl = (4 << 4) | 5
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        ip_total_len,
        1,
        0,
        64,
        6,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    tcp = struct.pack("!HHIIBBHHH", 12345, 443, 1000, 0, 5 << 4, 0x18, 4096, 0, 0)
    payload = b"x" * max(0, captured_len - len(eth) - len(ip) - len(tcp))
    return (eth + ip + tcp + payload)[:captured_len]


def test_snaplen_truncation_preserves_header_features_and_wire_payload_length():
    frame = _ethernet_ipv4_tcp_frame(ip_total_len=200, captured_len=96)
    item = _decode_truncated_ipv4(frame, original=214, timestamp=1.25, linktype=1)
    assert item is not None
    assert item["protocol"] == "tcp"
    assert item["sport"] == 12345
    assert item["dport"] == 443
    assert item["seq"] == 1000
    assert item["flags"] == 0x18
    assert item["win"] == 4096
    assert item["ttl"] == 64
    assert item["bytes"] == 214
    assert item["capture_truncated"] is True
    # 200-byte IPv4 total length - 20-byte IPv4 header - 20-byte TCP header.
    assert item["payload_len"] == 160


def test_non_ipv4_ethernet_frame_is_ignored():
    frame = b"\x00" * 12 + struct.pack("!H", 0x86DD) + b"\x00" * 80
    assert _decode_truncated_ipv4(frame, original=len(frame), timestamp=0.0, linktype=1) is None


def test_sequence_builder_requires_contiguous_8_plus_4_windows():
    n = HISTORY + HORIZON
    times = np.arange(n, dtype=np.int64) * 10
    x = np.zeros((n, 32, len(FEATURES)), dtype=np.float32)
    adj = np.zeros((n, 32, 32), dtype=np.float32)
    mask = np.ones((n, 32), dtype=np.float32)
    sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    assert sx.shape[0] == 1
    assert sa.shape[0] == 1
    assert sm.shape[0] == 1
    assert target.shape == (1, HORIZON, len(FEATURES))
    assert cutoffs.tolist() == [80]


def test_frozen_external_contract_constants_are_not_placeholder_values():
    assert EXPECTED_CAPTURE == "200601011400.dump"
    assert EXPECTED_RECORDS == 6_587_564
    assert EXPECTED_SNAPLEN == 96
    assert len(EXPECTED_MODEL_SHA256) == 64
    assert len(EXPECTED_SUPPORT_SHA256) == 64
    assert EXPECTED_MODEL_SHA256 != EXPECTED_SUPPORT_SHA256
