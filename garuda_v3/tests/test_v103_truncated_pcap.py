import struct
from pathlib import Path

import pytest

from garuda_v3.pcap_reader import packets


def _ether_ipv4(proto: int, transport: bytes, *, total_len: int, ihl_words: int = 5, ttl: int = 64, frag: int = 0):
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    ip = bytearray(max(20, ihl_words * 4))
    ip[0] = (4 << 4) | ihl_words
    ip[2:4] = struct.pack('!H', total_len)
    ip[6:8] = struct.pack('!H', frag)
    ip[8] = ttl
    ip[9] = proto
    ip[12:16] = b'\x0a\x00\x00\x01'
    ip[16:20] = b'\x0a\x00\x00\x02'
    return eth + bytes(ip) + transport


def _tcp(*, data_offset_words: int = 5):
    tcp = bytearray(20)
    tcp[0:2] = struct.pack('!H', 1234)
    tcp[2:4] = struct.pack('!H', 443)
    tcp[4:8] = struct.pack('!I', 77)
    tcp[12] = data_offset_words << 4
    tcp[13] = 0x12
    tcp[14:16] = struct.pack('!H', 64240)
    return bytes(tcp)


def _write_classic(path: Path, frame: bytes, *, original: int, snaplen: int = 96):
    gh = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, snaplen, 1)
    rec = struct.pack('<IIII', 1, 0, len(frame), original) + frame
    path.write_bytes(gh + rec)


def test_strict_default_still_rejects_snaplen_truncated_ipv4(tmp_path):
    p = tmp_path / 'strict.pcap'
    frame = _ether_ipv4(6, _tcp(), total_len=140)
    _write_classic(p, frame, original=154)
    with pytest.raises(ValueError, match='Truncated IPv4 packet'):
        list(packets(p, max_packets=10))


def test_tolerant_tcp_keeps_base_header_and_declared_payload_length(tmp_path):
    p = tmp_path / 'tcp.pcap'
    frame = _ether_ipv4(6, _tcp(), total_len=140)
    _write_classic(p, frame, original=154)
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1
    row = rows[0]
    assert row['protocol'] == 'tcp'
    assert (row['sport'], row['dport']) == (1234, 443)
    assert row['flags'] == 0x12
    assert row['win'] == 64240
    assert row['payload_len'] == 100
    assert audit['decoded_ipv4'] == 1
    assert audit['full_tcp'] == 1
    assert audit['degraded_short_tcp'] == 0


def test_tolerant_tcp_options_may_be_truncated_after_base_header(tmp_path):
    p = tmp_path / 'tcp-options.pcap'
    # Declared TCP header is 40 bytes but only the base 20 bytes are captured.
    frame = _ether_ipv4(6, _tcp(data_offset_words=10), total_len=180)
    _write_classic(p, frame, original=194)
    rows = list(packets(p, max_packets=10, allow_truncated=True))
    assert rows[0]['protocol'] == 'tcp'
    assert rows[0]['payload_len'] == 120


def test_tolerant_short_tcp_degrades_to_other(tmp_path):
    p = tmp_path / 'short-tcp.pcap'
    frame = _ether_ipv4(6, b'\x00' * 10, total_len=100)
    _write_classic(p, frame, original=114)
    audit = {}
    row = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))[0]
    assert row['protocol'] == 'other'
    assert row['sport'] == 0 and row['dport'] == 0
    assert row['ttl'] == 64
    assert row['payload_len'] == 80
    assert audit['degraded_short_tcp'] == 1


def test_tolerant_short_udp_degrades_to_other(tmp_path):
    p = tmp_path / 'short-udp.pcap'
    frame = _ether_ipv4(17, b'\x00' * 4, total_len=80)
    _write_classic(p, frame, original=94)
    audit = {}
    row = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))[0]
    assert row['protocol'] == 'other'
    assert row['payload_len'] == 60
    assert audit['degraded_short_udp'] == 1


def test_tolerant_short_ip_options_degrades_to_other(tmp_path):
    p = tmp_path / 'short-ip-options.pcap'
    # IHL declares 60 bytes but only 30 IPv4 bytes are captured.
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    ip = bytearray(30)
    ip[0] = 0x4F
    ip[2:4] = struct.pack('!H', 120)
    ip[8] = 55
    ip[9] = 6
    ip[12:16] = b'\x0a\x00\x00\x01'
    ip[16:20] = b'\x0a\x00\x00\x02'
    _write_classic(p, eth + bytes(ip), original=134)
    audit = {}
    row = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))[0]
    assert row['protocol'] == 'other'
    assert row['ttl'] == 55
    assert row['payload_len'] == 60
    assert audit['degraded_short_ip_options'] == 1


def test_nonfirst_fragment_stays_other_and_is_audited(tmp_path):
    p = tmp_path / 'fragment.pcap'
    frame = _ether_ipv4(6, b'\x00' * 20, total_len=40, frag=1)
    _write_classic(p, frame, original=len(frame))
    audit = {}
    row = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))[0]
    assert row['protocol'] == 'other'
    assert audit['nonfirst_fragment'] == 1
