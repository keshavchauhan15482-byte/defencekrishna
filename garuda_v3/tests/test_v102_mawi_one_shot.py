import struct
from pathlib import Path

import pytest

from garuda_v3.v102_mawi_one_shot import (
    EXPECTED_MODEL_SHA256,
    EXPECTED_SNAPLEN,
    EXPECTED_SUPPORT_SHA256,
    V102ContractError,
    mawi_packets,
)


def _write_truncated_tcp(path: Path, snaplen: int = 96):
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack('!H', 140)  # full IPv4 length, larger than captured bytes
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = b'\x0a\x00\x00\x01'
    ip[16:20] = b'\x0a\x00\x00\x02'
    tcp = bytearray(20)
    tcp[0:2] = struct.pack('!H', 1234)
    tcp[2:4] = struct.pack('!H', 80)
    tcp[4:8] = struct.pack('!I', 7)
    tcp[12] = 0x50
    tcp[13] = 0x02
    tcp[14:16] = struct.pack('!H', 64240)
    frame = eth + bytes(ip) + bytes(tcp)
    global_header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, snaplen, 1)
    record = struct.pack('<IIII', 1, 0, len(frame), 154) + frame
    path.write_bytes(global_header + record)


def test_truncated_payload_length_is_derived_from_ipv4_total_length(tmp_path):
    p = tmp_path / '200601011400.dump'
    _write_truncated_tcp(p)
    rows = list(mawi_packets(p))
    assert len(rows) == 1
    assert rows[0]['protocol'] == 'tcp'
    assert rows[0]['sport'] == 1234
    assert rows[0]['dport'] == 80
    assert rows[0]['payload_len'] == 100
    assert rows[0]['ttl'] == 64
    assert rows[0]['win'] == 64240


def test_unexpected_snaplen_fails_closed(tmp_path):
    p = tmp_path / '200601011400.dump'
    _write_truncated_tcp(p, snaplen=128)
    with pytest.raises(V102ContractError, match='Unexpected PCAP contract'):
        list(mawi_packets(p))


def test_runtime_hashes_are_frozen_v101_values():
    assert len(EXPECTED_MODEL_SHA256) == 64
    assert len(EXPECTED_SUPPORT_SHA256) == 64
    assert EXPECTED_SNAPLEN == 96
