"""Create an audited classic-PCAP derivative by dropping only an incomplete EOF record.

Some committed CIC-IDS2018 victim-capture members end in a partial packet record.
The strict runtime decoder correctly rejects those files.  This utility is for
offline dataset preparation only: it copies complete records byte-for-byte and
may remove a single incomplete record at EOF.  Any structural error before EOF
still fails closed.
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


def clean(source: str | Path, output: str | Path, audit_path: str | Path | None = None) -> dict:
    source, output = Path(source), Path(output)
    if output.exists():
        raise ValueError("Output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    kept = 0
    removed_tail = None
    with source.open("rb") as src, output.open("xb") as dst:
        header = src.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("Unsupported/truncated classic PCAP header")
        endian, _ = MAGIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if major != 2 or minor != 4 or linktype not in (1, 101):
            raise ValueError("Supported PCAP is v2.4 Ethernet or raw IPv4")
        dst.write(header)
        while True:
            record = src.read(16)
            if not record:
                break
            if len(record) != 16:
                removed_tail = {"reason": "incomplete_record_header", "bytes_present": len(record)}
                break
            sec, sub, captured, original = struct.unpack(endian + "IIII", record)
            if captured > 262144 or captured > snaplen or captured > original:
                raise ValueError(f"Invalid record length before EOF at record {kept + 1}")
            payload = src.read(captured)
            if len(payload) != captured:
                removed_tail = {
                    "reason": "incomplete_record_payload",
                    "bytes_present": len(payload),
                    "bytes_expected": captured,
                    "record_index": kept + 1,
                }
                break
            dst.write(record)
            dst.write(payload)
            kept += 1
    if kept == 0:
        output.unlink(missing_ok=True)
        raise ValueError("No complete packet records")
    audit = {
        "method": "copy complete classic-PCAP records byte-for-byte; drop at most one incomplete EOF record; no imputation",
        "source": str(source),
        "output": str(output),
        "original_sha256": sha256(source),
        "derivative_sha256": sha256(output),
        "complete_records": kept,
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
    args = parser.parse_args()
    print(json.dumps(clean(args.source, args.output, args.audit), indent=2))


if __name__ == "__main__":
    main()
