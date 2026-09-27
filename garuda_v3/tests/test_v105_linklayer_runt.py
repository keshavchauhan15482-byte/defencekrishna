from __future__ import annotations

import struct
from pathlib import Path

import pytest

from garuda_v3.pcap_reader import packets


def _global_header(*, snaplen: int = 96) -> bytes:
    return b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, snaplen, 1)


def _record(frame: bytes, *, sec: int = 1, original: int | None = None) -> bytes:
    if original is None:
        original = len(frame)
    return struct.pack('<IIII', sec, 0, len(frame), int(original)) + frame


def _write(path: Path, *frames: tuple[bytes, int | None]) -> None:
    body = bytearray(_global_header())
    for idx, (frame, original) in enumerate(frames, start=1):
        body += _record(frame, sec=idx, original=original)
    path.write_bytes(bytes(body))


def _tcp_ipv4_frame() -> bytes:
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
    tcp[4:8] = struct.pack('!I', 11)
    tcp[12] = 5 << 4
    tcp[13] = 0x12
    tcp[14:16] = struct.pack('!H', 4096)
    return eth + bytes(ip) + bytes(tcp)


def test_strict_mode_still_fails_on_ethernet_runt(tmp_path):
    p = tmp_path / 'strict-runt.pcap'
    _write(p, (b'\x00' * 10, 60))
    with pytest.raises(ValueError, match='Truncated Ethernet frame'):
        list(packets(p, max_packets=10))


def test_tolerant_mode_skips_ethernet_runt_and_continues(tmp_path):
    p = tmp_path / 'tolerant-runt.pcap'
    valid = _tcp_ipv4_frame()
    _write(p, (b'\x00' * 10, 60), (valid, len(valid)))
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1
    assert rows[0]['protocol'] == 'tcp'
    assert (rows[0]['sport'], rows[0]['dport']) == (1234, 443)
    assert audit['skipped_truncated_ethernet'] == 1
    assert audit['decoded_ipv4'] == 1


def test_vlan_runt_is_strict_error_but_tolerant_skip(tmp_path):
    # Ethernet EtherType says 802.1Q but the required four-byte VLAN tag is absent.
    vlan_runt = b'\x00' * 12 + struct.pack('!H', 0x8100) + b'\x00\x01'
    strict = tmp_path / 'strict-vlan.pcap'
    tolerant = tmp_path / 'tolerant-vlan.pcap'
    _write(strict, (vlan_runt, 60))
    _write(tolerant, (vlan_runt, 60), (_tcp_ipv4_frame(), 54))
    with pytest.raises(ValueError, match='Truncated VLAN header'):
        list(packets(strict, max_packets=10))
    audit = {}
    rows = list(packets(tolerant, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1 and rows[0]['protocol'] == 'tcp'
    assert audit['skipped_truncated_vlan'] == 1


def test_tolerant_short_ipv4_base_header_is_skipped_not_fabricated(tmp_path):
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    short_ip = eth + b'\x45' + b'\x00' * 9
    p = tmp_path / 'short-ip.pcap'
    _write(p, (short_ip, 60), (_tcp_ipv4_frame(), 54))
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1
    assert rows[0]['src'] == '10.0.0.1'
    assert audit['skipped_truncated_ipv4_header'] == 1


def test_non_ipv4_frame_is_normal_skip_not_runt(tmp_path):
    arp = b'\x00' * 12 + struct.pack('!H', 0x0806) + b'\x00' * 28
    p = tmp_path / 'arp.pcap'
    _write(p, (arp, len(arp)), (_tcp_ipv4_frame(), 54))
    audit = {}
    rows = list(packets(p, max_packets=10, allow_truncated=True, audit=audit))
    assert len(rows) == 1
    assert audit['non_ipv4'] == 1
    assert audit['skipped_truncated_ethernet'] == 0
    assert audit['skipped_truncated_vlan'] == 0
    assert audit['skipped_truncated_ipv4_header'] == 0
