"""Bounded dependency-free PCAP/PCAPNG IPv4 TCP/UDP decoder.

The SIH datasets include captures whose filename ends in ``.pcap`` while the bytes are
actually PCAPNG.  Format is therefore detected from magic bytes, never from filename.
Supported link types are Ethernet (DLT_EN10MB=1) and raw IPv4 (DLT_RAW=101).
"""
from __future__ import annotations

import socket
import struct

_CLASSIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e6),
    b'\xa1\xb2\xc3\xd4': ('>', 1e6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e9),
    b'\xa1\xb2\x3c\x4d': ('>', 1e9),
}
_PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


def _decode_ipv4(data: bytes, *, original: int, timestamp: float, linktype: int):
    offset = 0
    if linktype == 1:
        if len(data) < 14:
            raise ValueError('Truncated Ethernet frame')
        kind = struct.unpack('!H', data[12:14])[0]
        offset = 14
        for _ in range(2):
            if kind in (0x8100, 0x88A8):
                if len(data) < offset + 4:
                    raise ValueError('Truncated VLAN header')
                kind = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                offset += 4
        if kind != 0x0800:
            return None
    elif linktype != 101:
        raise ValueError(f'Unsupported link type {linktype}; expected Ethernet(1) or raw IPv4(101)')

    ip = data[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 15) * 4
    length = struct.unpack('!H', ip[2:4])[0]
    if ihl < 20 or length < ihl or len(ip) < length:
        raise ValueError('Truncated IPv4 packet; use full-snaplen capture')
    frag = struct.unpack('!H', ip[6:8])[0]
    proto = ip[9]
    item = dict(
        t=float(timestamp),
        src=socket.inet_ntoa(ip[12:16]),
        dst=socket.inet_ntoa(ip[16:20]),
        bytes=int(original),
        ttl=int(ip[8]),
        frag=bool(frag & 0x3FFF),
        protocol='other',
        sport=0,
        dport=0,
        flags=0,
        win=0,
        seq=None,
        payload_len=0,
    )
    if frag & 0x1FFF:
        return item

    transport = ip[ihl:length]
    if proto == 6:
        if len(transport) < 20:
            raise ValueError('Truncated TCP header')
        tcp_len = (transport[12] >> 4) * 4
        if tcp_len < 20 or tcp_len > len(transport):
            raise ValueError('Invalid TCP data offset')
        sport, dport, seq = struct.unpack('!HHI', transport[:8])
        item.update(
            protocol='tcp', sport=int(sport), dport=int(dport), seq=int(seq),
            flags=int(transport[13]), win=struct.unpack('!H', transport[14:16])[0],
            payload_len=len(transport) - tcp_len,
        )
    elif proto == 17:
        if len(transport) < 8:
            raise ValueError('Truncated UDP header')
        sport, dport = struct.unpack('!HH', transport[:4])
        item.update(protocol='udp', sport=int(sport), dport=int(dport), payload_len=max(0, len(transport) - 8))
    return item


def _classic_packets(f, first4: bytes, max_packets: int):
    tail = f.read(20)
    header = first4 + tail
    if len(header) != 24:
        raise ValueError('Truncated PCAP header')
    endian, unit = _CLASSIC[first4]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHIIII', header[4:])
    if major != 2 or minor != 4 or linktype not in (1, 101):
        raise ValueError('Supported classic PCAP: v2.4 Ethernet or raw IPv4')
    count = 0
    while True:
        record = f.read(16)
        if not record:
            break
        if len(record) != 16:
            raise ValueError('Truncated packet record')
        sec, sub, captured, original = struct.unpack(endian + 'IIII', record)
        if captured > 262144 or captured > snaplen or captured > original:
            raise ValueError('Invalid capture length')
        data = f.read(captured)
        if len(data) != captured:
            raise ValueError('Truncated packet bytes')
        count += 1
        if count > max_packets:
            raise ValueError('Packet count limit exceeded')
        item = _decode_ipv4(data, original=original, timestamp=sec + sub / unit, linktype=linktype)
        if item is not None:
            yield item


def _option_ts_resolution(body: bytes, endian: str) -> float:
    """Parse IDB options; default PCAPNG timestamp resolution is microseconds."""
    pos = 8  # linktype(2), reserved(2), snaplen(4)
    resolution = 1e-6
    while pos + 4 <= len(body):
        code, length = struct.unpack(endian + 'HH', body[pos:pos + 4])
        pos += 4
        if code == 0:
            break
        value = body[pos:pos + length]
        pos += (length + 3) & ~3
        if code == 9 and value:
            raw = value[0]
            resolution = 2.0 ** -(raw & 0x7F) if raw & 0x80 else 10.0 ** -raw
    return float(resolution)


def _pcapng_packets(f, first4: bytes, max_packets: int):
    # The first section header begins with magic already consumed. Read total length +
    # byte-order magic so section endianness can be established before parsing length.
    head_tail = f.read(8)
    if len(head_tail) != 8:
        raise ValueError('Truncated PCAPNG section header')
    bom = head_tail[4:8]
    if bom == b'\x4d\x3c\x2b\x1a':
        endian = '<'
    elif bom == b'\x1a\x2b\x3c\x4d':
        endian = '>'
    else:
        raise ValueError('Invalid PCAPNG byte-order magic')
    total = struct.unpack(endian + 'I', head_tail[:4])[0]
    if total < 28 or total % 4:
        raise ValueError('Invalid PCAPNG section length')
    rest = f.read(total - 12)
    if len(rest) != total - 12 or struct.unpack(endian + 'I', rest[-4:])[0] != total:
        raise ValueError('Truncated or inconsistent PCAPNG section header')

    interfaces: list[tuple[int, int, float]] = []  # linktype, snaplen, ts_resolution
    count = 0
    while True:
        prefix = f.read(8)
        if not prefix:
            break
        if len(prefix) != 8:
            raise ValueError('Truncated PCAPNG block header')

        # A new Section Header Block can change byte order and resets interface ids.
        if prefix[:4] == _PCAPNG_MAGIC:
            bom = f.read(4)
            if len(bom) != 4:
                raise ValueError('Truncated PCAPNG section header')
            if bom == b'\x4d\x3c\x2b\x1a':
                new_endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                new_endian = '>'
            else:
                raise ValueError('Invalid PCAPNG byte-order magic')
            block_total = struct.unpack(new_endian + 'I', prefix[4:8])[0]
            if block_total < 28 or block_total % 4:
                raise ValueError('Invalid PCAPNG section length')
            remaining = f.read(block_total - 12)
            if len(remaining) != block_total - 12 or struct.unpack(new_endian + 'I', remaining[-4:])[0] != block_total:
                raise ValueError('Truncated or inconsistent PCAPNG section')
            endian = new_endian
            interfaces = []
            continue

        block_type, block_total = struct.unpack(endian + 'II', prefix)
        if block_total < 12 or block_total % 4 or block_total > 64 * 1024 * 1024:
            raise ValueError('Invalid PCAPNG block length')
        rest = f.read(block_total - 8)
        if len(rest) != block_total - 8:
            raise ValueError('Truncated PCAPNG block')
        if struct.unpack(endian + 'I', rest[-4:])[0] != block_total:
            raise ValueError('PCAPNG trailing block length mismatch')
        body = rest[:-4]

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise ValueError('Truncated PCAPNG interface block')
            linktype = struct.unpack(endian + 'H', body[:2])[0]
            snaplen = struct.unpack(endian + 'I', body[4:8])[0]
            if linktype not in (1, 101):
                # Keep interface numbering stable; unsupported interfaces are marked.
                interfaces.append((int(linktype), int(snaplen), _option_ts_resolution(body, endian)))
            else:
                interfaces.append((int(linktype), int(snaplen), _option_ts_resolution(body, endian)))
            continue

        if block_type != 6:  # Enhanced Packet Block carries interface + timestamp.
            continue
        if len(body) < 20:
            raise ValueError('Truncated PCAPNG enhanced packet block')
        interface_id, ts_hi, ts_lo, captured, original = struct.unpack(endian + 'IIIII', body[:20])
        if interface_id >= len(interfaces):
            raise ValueError('PCAPNG packet references unknown interface')
        linktype, snaplen, resolution = interfaces[interface_id]
        if linktype not in (1, 101):
            continue
        if captured > 262144 or (snaplen and captured > snaplen) or captured > original:
            raise ValueError('Invalid PCAPNG capture length')
        if 20 + captured > len(body):
            raise ValueError('Truncated PCAPNG packet bytes')
        data = body[20:20 + captured]
        count += 1
        if count > max_packets:
            raise ValueError('Packet count limit exceeded')
        timestamp = ((int(ts_hi) << 32) | int(ts_lo)) * resolution
        item = _decode_ipv4(data, original=original, timestamp=timestamp, linktype=linktype)
        if item is not None:
            yield item


def packets(path, max_packets=250000):
    if max_packets < 1:
        raise ValueError('max_packets must be positive')
    with open(path, 'rb') as f:
        first4 = f.read(4)
        if len(first4) != 4:
            raise ValueError('Truncated capture header')
        if first4 in _CLASSIC:
            yield from _classic_packets(f, first4, int(max_packets))
        elif first4 == _PCAPNG_MAGIC:
            yield from _pcapng_packets(f, first4, int(max_packets))
        else:
            raise ValueError('Unsupported capture format; expected classic PCAP or PCAPNG')
