import struct
from pathlib import Path

import pytest

from garuda_v3.pcap_reader import packets


def _valid_tcp_frame():
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack('!H', 40)
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = b'\x0a\x00\x00\x01'
    ip[16:20] = b'\x0a\x00\x00\x02'
    tcp = bytearray(20)
    tcp[0:2] = struct.pack('!H', 1234)
    tcp[2:4] = struct.pack('!H', 443)
    tcp[12] = 5 << 4
    tcp[13] = 0x12
    tcp[14:16] = struct.pack('!H', 64240)
    return eth + bytes(ip) + bytes(tcp)


def _write_classic(path: Path, frames, *, snaplen=96):
    gh = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, snaplen, 1)
    chunks = [gh]
    for i, frame in enumerate(frames, start=1):
        chunks.append(struct.pack('<IIII', i, 0, len(frame), len(frame)))
        chunks.append(frame)
    path.write_bytes(b''.join(chunks))


def test_strict_mode_still_rejects_truncated_ethernet(tmp_path):
    p = tmp_path / 'runt-ethernet.pcap'
    _write_classic(p, [b'\x00' * 10])
    with pytest.raises(ValueError, match='Truncated Ethernet frame'):
        list(packets(p, max_packets=10))


def test_tolerant_mode_skips_runt_ethernet_and_continues(tmp_path):
    p = tmp_path / 'runt-then-valid.pcap'
    _write_classic(p, [b'\x00' * 10, _valid_tcp_frame()])
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1
    assert rows[0]['protocol'] == 'tcp'
    assert (rows[0]['sport'], rows[0]['dport']) == (1234, 443)
    assert audit['skipped_truncated_ethernet'] == 1
    assert audit['decoded_ipv4'] == 1


def test_strict_mode_still_rejects_truncated_vlan(tmp_path):
    p = tmp_path / 'runt-vlan.pcap'
    frame = b'\x00' * 12 + struct.pack('!H', 0x8100) + b'\x00\x01'
    _write_classic(p, [frame])
    with pytest.raises(ValueError, match='Truncated VLAN header'):
        list(packets(p, max_packets=10))


def test_tolerant_mode_skips_truncated_vlan_without_fabrication(tmp_path):
    p = tmp_path / 'runt-vlan.pcap'
    frame = b'\x00' * 12 + struct.pack('!H', 0x8100) + b'\x00\x01'
    _write_classic(p, [frame])
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert rows == []
    assert audit['skipped_truncated_vlan'] == 1
    assert audit.get('decoded_ipv4', 0) == 0


def test_tolerant_mode_audits_short_ipv4_base_header(tmp_path):
    p = tmp_path / 'short-ip.pcap'
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    _write_classic(p, [eth + b'\x45' + b'\x00' * 9])
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert rows == []
    assert audit['skipped_truncated_ipv4_header'] == 1
    assert audit.get('decoded_ipv4', 0) == 0


def test_v105_reader_does_not_turn_runt_into_other_protocol_packet(tmp_path):
    p = tmp_path / 'only-runt.pcap'
    _write_classic(p, [b'\xff' * 8])
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert rows == []
    assert audit['skipped_truncated_ethernet'] == 1
    assert audit.get('other_protocol', 0) == 0
