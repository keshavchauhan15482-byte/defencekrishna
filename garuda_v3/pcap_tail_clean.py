"""Create an audited classic-PCAP derivative without partial network states.

Some committed CIC-IDS2018 victim captures contain an incomplete EOF record or
snaplen-truncated IPv4 packet.  The strict runtime decoder correctly rejects
those files.  This offline dataset-preparation utility never imputes bytes: it
copies complete records byte-for-byte and excludes the *entire 10-second
window* touching any structurally incomplete packet evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while block := handle.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def _packet_error(payload: bytes, linktype: int) -> str | None:
    """Mirror the strict decoder's structural checks without interpreting labels."""
    offset = 0
    if linktype == 1:
        if len(payload) < 14:
            return "truncated_ethernet_frame"
        kind = struct.unpack("!H", payload[12:14])[0]
        offset = 14
        for _ in range(2):
            if kind in (0x8100, 0x88A8):
                if len(payload) < offset + 4:
                    return "truncated_vlan_header"
                kind = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
                offset += 4
        if kind != 0x0800:
            return None
    ip = payload[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 15) * 4
    length = struct.unpack("!H", ip[2:4])[0]
    if ihl < 20 or length < ihl:
        return "invalid_ipv4_header_length"
    if len(ip) < length:
        return "truncated_ipv4_packet"
    fragment = struct.unpack("!H", ip[6:8])[0]
    if fragment & 0x1FFF:
        return None
    transport = ip[ihl:length]
    protocol = ip[9]
    if protocol == 6:
        if len(transport) < 20:
            return "truncated_tcp_header"
        tcp_len = (transport[12] >> 4) * 4
        if tcp_len < 20 or tcp_len > len(transport):
            return "invalid_tcp_data_offset"
    elif protocol == 17 and len(transport) < 8:
        return "truncated_udp_header"
    return None


def clean(source: str | Path, output: str | Path, audit_path: str | Path | None = None,
          window_seconds: int = 10) -> dict:
    source, output = Path(source), Path(output)
    if output.exists():
        raise ValueError("Output already exists")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    output.parent.mkdir(parents=True, exist_ok=True)

    records: list[tuple[bytes, bytes, int]] = []
    invalid_windows: set[int] = set()
    invalid_records: list[dict] = []
    removed_tail = None
    last_bucket = None

    with source.open("rb") as src:
        header = src.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("Unsupported/truncated classic PCAP header")
        endian, unit = MAGIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if major != 2 or minor != 4 or linktype not in (1, 101):
            raise ValueError("Supported PCAP is v2.4 Ethernet or raw IPv4")

        record_index = 0
        while True:
            record = src.read(16)
            if not record:
                break
            record_index += 1
            if len(record) != 16:
                if last_bucket is not None:
                    invalid_windows.add(last_bucket)
                removed_tail = {"reason": "incomplete_record_header", "bytes_present": len(record), "record_index": record_index}
                break
            sec, sub, captured, original = struct.unpack(endian + "IIII", record)
            bucket = int((sec + sub / unit) // window_seconds) * window_seconds
            last_bucket = bucket
            if captured > 262144 or captured > snaplen or captured > original:
                raise ValueError(f"Invalid record length before EOF at record {record_index}")
            payload = src.read(captured)
            if len(payload) != captured:
                invalid_windows.add(bucket)
                removed_tail = {
                    "reason": "incomplete_record_payload", "bytes_present": len(payload),
                    "bytes_expected": captured, "record_index": record_index, "window": bucket,
                }
                break
            reason = _packet_error(payload, linktype)
            if reason:
                invalid_windows.add(bucket)
                if len(invalid_records) < 100:
                    invalid_records.append({"record_index": record_index, "window": bucket, "reason": reason})
            records.append((record, payload, bucket))

    retained = [(record, payload) for record, payload, bucket in records if bucket not in invalid_windows]
    if not retained:
        raise ValueError("No complete packet windows remain after integrity filtering")

    with output.open("xb") as dst:
        dst.write(header)
        for record, payload in retained:
            dst.write(record)
            dst.write(payload)

    audit = {
        "method": "copy complete records byte-for-byte; exclude every 10-second window touching incomplete packet evidence; no imputation",
        "source": str(source), "output": str(output), "window_seconds": window_seconds,
        "original_sha256": sha256(source), "derivative_sha256": sha256(output),
        "complete_records_seen": len(records), "complete_records": len(retained),
        "excluded_windows": sorted(invalid_windows),
        "invalid_records_sample": invalid_records,
        "removed_tail": removed_tail,
    }
    if audit_path:
        audit_file = Path(audit_path)
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        if audit_file.exists():
            raise ValueError("Audit output already exists")
        audit_file.write_text(json.dumps(audit, indent=2) + "\n")
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--audit", required=True)
    parser.add_argument("--window-seconds", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(clean(args.source, args.output, args.audit, args.window_seconds), indent=2))


if __name__ == "__main__":
    main()
