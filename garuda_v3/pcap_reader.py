"""Bounded dependency-free PCAP/PCAPNG IPv4 TCP/UDP decoder.

Format is detected from magic bytes, never filename. Supported link types are
Ethernet (DLT_EN10MB=1) and raw IPv4 (DLT_RAW=101).

The historical behavior remains strict by default. V103 added an explicit
``allow_truncated=True`` mode for snaplen-limited network/transport payloads.
V105 extends only that opt-in tolerant path to safely skip link-layer runt records
whose Ethernet/VLAN/IP base headers are unavailable. Such records cannot support
network telemetry, so tolerant mode audits and skips them rather than fabricating
fields. Strict mode retains the historical fail-closed Ethernet/VLAN behavior.
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

_AUDIT_KEYS = (
    'decoded_ipv4', 'full_tcp', 'full_udp', 'degraded_short_ip_options',
    'degraded_short_tcp', 'degraded_short_udp', 'nonfirst_fragment',
    'other_protocol', 'skipped_truncated_ethernet', 'skipped_truncated_vlan',
    'skipped_truncated_ipv4_header', 'non_ipv4',
)


def _bump(audit, key: str) -> None:
    if audit is not None:
        audit[key] = int(audit.get(key, 0)) + 1


def _base_item(ip: bytes, *, original: int, timestamp: float, frag: int, payload_len: int):
    return dict(
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
        payload_len=max(0, int(payload_len)),
    )


def _decode_ipv4(
    data: bytes,
    *,
    original: int,
    timestamp: float,
    linktype: int,
    allow_truncated: bool = False,
    audit=None,
):
    offset = 0
    if linktype == 1:
        # IEEE 802.3/Ethernet II requires 14 bytes before EtherType can be read.
        # In tolerant mode a shorter record cannot provide trustworthy IP telemetry,
        # so skip it with an explicit audit marker instead of inventing headers.
        if len(data) < 14:
            if allow_truncated:
                _bump(audit, 'skipped_truncated_ethernet')
                return None
            raise ValueError('Truncated Ethernet frame')
        kind = struct.unpack('!H', data[12:14])[0]
        offset = 14
        for _ in range(2):
            if kind in (0x8100, 0x88A8):
                if len(data) < offset + 4:
                    if allow_truncated:
                        _bump(audit, 'skipped_truncated_vlan')
                        return None
                    raise ValueError('Truncated VLAN header')
                kind = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                offset += 4
        if kind != 0x0800:
            _bump(audit, 'non_ipv4')
            return None
    elif linktype != 101:
        raise ValueError(f'Unsupported link type {linktype}; expected Ethernet(1) or raw IPv4(101)')

    ip = data[offset:]
    # A captured IPv4 base header requires 20 bytes. Historical strict behavior for
    # this case was to ignore the undecodable record rather than raise; preserve it.
    # Tolerant mode additionally makes that skip visible in the audit contract.
    if len(ip) < 20:
        if allow_truncated:
            _bump(audit, 'skipped_truncated_ipv4_header')
        return None
    if ip[0] >> 4 != 4:
        _bump(audit, 'non_ipv4')
        return None
    ihl = (ip[0] & 15) * 4
    length = struct.unpack('!H', ip[2:4])[0]
    if ihl < 20 or length < ihl:
        raise ValueError('Invalid IPv4 header/total length')
    if not allow_truncated and len(ip) < length:
        raise ValueError('Truncated IPv4 packet; use full-snaplen capture')

    frag = struct.unpack('!H', ip[6:8])[0]
    proto = ip[9]
    declared_transport_len = max(0, length - ihl)

    # In tolerant mode an IP options area can itself be snaplen-truncated. The
    # base IPv4 header still gives stable endpoint/TTL/fragment telemetry, but
    # transport location is not trustworthy, so degrade deterministically.
    if len(ip) < ihl:
        if not allow_truncated:
            raise ValueError('Truncated IPv4 packet; use full-snaplen capture')
        item = _base_item(
            ip, original=original, timestamp=timestamp, frag=frag,
            payload_len=declared_transport_len,
        )
        _bump(audit, 'decoded_ipv4')
        _bump(audit, 'degraded_short_ip_options')
        return item

    item = _base_item(
        ip, original=original, timestamp=timestamp, frag=frag,
        payload_len=declared_transport_len if allow_truncated else 0,
    )
    _bump(audit, 'decoded_ipv4')

    if frag & 0x1FFF:
        _bump(audit, 'nonfirst_fragment')
        return item

    captured_transport = ip[ihl:min(len(ip), length)]
    if proto == 6:
        if len(captured_transport) < 20:
            if allow_truncated:
                _bump(audit, 'degraded_short_tcp')
                return item
            raise ValueError('Truncated TCP header')
        tcp_len = (captured_transport[12] >> 4) * 4
        if tcp_len < 20 or tcp_len > declared_transport_len:
            if allow_truncated:
                _bump(audit, 'degraded_short_tcp')
                return item
            raise ValueError('Invalid TCP data offset')
        if not allow_truncated and tcp_len > len(captured_transport):
            raise ValueError('Invalid TCP data offset')
        sport, dport, seq = struct.unpack('!HHI', captured_transport[:8])
        item.update(
            protocol='tcp', sport=int(sport), dport=int(dport), seq=int(seq),
            flags=int(captured_transport[13]),
            win=struct.unpack('!H', captured_transport[14:16])[0],
            payload_len=max(0, declared_transport_len - tcp_len)
            if allow_truncated else len(captured_transport) - tcp_len,
        )
        _bump(audit, 'full_tcp')
    elif proto == 17:
        if len(captured_transport) < 8:
            if allow_truncated:
                _bump(audit, 'degraded_short_udp')
                return item
            raise ValueError('Truncated UDP header')
        sport, dport = struct.unpack('!HH', captured_transport[:4])
        item.update(
            protocol='udp', sport=int(sport), dport=int(dport),
            payload_len=max(0, declared_transport_len - 8)
            if allow_truncated else max(0, len(captured_transport) - 8),
        )
        _bump(audit, 'full_udp')
    else:
        _bump(audit, 'other_protocol')
    return item


def _classic_packets(f, first4: bytes, max_packets: int, *, allow_truncated=False, audit=None):
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
        item = _decode_ipv4(
            data, original=original, timestamp=sec + sub / unit,
            linktype=linktype, allow_truncated=allow_truncated, audit=audit,
        )
        if item is not None:
            yield item


def _option_ts_resolution(body: bytes, endian: str) -> float:
    """Parse IDB options; default PCAPNG timestamp resolution is microseconds."""
    pos = 8
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


def _pcapng_packets(f, first4: bytes, max_packets: int, *, allow_truncated=False, audit=None):
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

    interfaces: list[tuple[int, int, float]] = []
    count = 0
    while True:
        prefix = f.read(8)
        if not prefix:
            break
        if len(prefix) != 8:
            raise ValueError('Truncated PCAPNG block header')
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

        if block_type == 1:
            if len(body) < 8:
                raise ValueError('Truncated PCAPNG interface block')
            linktype = struct.unpack(endian + 'H', body[:2])[0]
            snaplen = struct.unpack(endian + 'I', body[4:8])[0]
            interfaces.append((int(linktype), int(snaplen), _option_ts_resolution(body, endian)))
            continue
        if block_type != 6:
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
        item = _decode_ipv4(
            data, original=original, timestamp=timestamp, linktype=linktype,
            allow_truncated=allow_truncated, audit=audit,
        )
        if item is not None:
            yield item


def packets(path, max_packets=250000, *, allow_truncated=False, audit=None):
    """Yield decoded IPv4 packet telemetry.

    ``allow_truncated`` is opt-in so historical callers retain strict behavior.
    In tolerant mode, snaplen-truncated network/transport records may degrade to
    stable IP telemetry, while link-layer runts that cannot establish IP identity
    are skipped and audited. No missing packet bytes are fabricated.
    """
    if max_packets < 1:
        raise ValueError('max_packets must be positive')
    if audit is not None:
        for key in _AUDIT_KEYS:
            audit.setdefault(key, 0)
    with open(path, 'rb') as f:
        first4 = f.read(4)
        if len(first4) != 4:
            raise ValueError('Truncated capture header')
        if first4 in _CLASSIC:
            yield from _classic_packets(
                f, first4, int(max_packets), allow_truncated=allow_truncated, audit=audit,
            )
        elif first4 == _PCAPNG_MAGIC:
            yield from _pcapng_packets(
                f, first4, int(max_packets), allow_truncated=allow_truncated, audit=audit,
            )
        else:
            raise ValueError('Unsupported capture format; expected classic PCAP or PCAPNG')
