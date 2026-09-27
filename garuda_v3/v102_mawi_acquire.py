"""V102 acquisition-only integrity freeze for the preregistered MAWI capture.

This script is deliberately prohibited from decoding packet records or invoking any
model. It only hashes the exact registered compressed object, streams the decompressed
bytes into SHA-256, and inspects the classic-PCAP global header.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
from pathlib import Path

PREREG_DEFAULT = Path("garuda_v3/artifacts/certification/v102/preregistration.json")

CLASSIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inspect_gzip_pcap(path: Path) -> dict:
    decompressed_hash = hashlib.sha256()
    decompressed_bytes = 0
    header = b""
    with gzip.open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            if len(header) < 24:
                need = 24 - len(header)
                header += block[:need]
            decompressed_hash.update(block)
            decompressed_bytes += len(block)
    if len(header) != 24:
        raise RuntimeError("Decompressed object is too short for a classic PCAP global header")
    magic = header[:4]
    if magic not in CLASSIC:
        raise RuntimeError(f"Expected classic PCAP magic, observed {magic.hex()}")
    endian, ts_resolution = CLASSIC[magic]
    major, minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(endian + "HHiiii", header[4:24])
    if (major, minor) != (2, 4):
        raise RuntimeError(f"Expected PCAP v2.4, observed {major}.{minor}")
    return {
        "decompressed_sha256": decompressed_hash.hexdigest(),
        "decompressed_bytes": int(decompressed_bytes),
        "pcap_global_header": {
            "magic_hex": magic.hex(),
            "endianness": "little" if endian == "<" else "big",
            "timestamp_resolution": ts_resolution,
            "version_major": int(major),
            "version_minor": int(minor),
            "thiszone": int(thiszone),
            "sigfigs": int(sigfigs),
            "snaplen": int(snaplen),
            "linktype": int(linktype),
        },
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prereg", type=Path, default=PREREG_DEFAULT)
    p.add_argument("--capture-gz", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    prereg = json.loads(args.prereg.read_text(encoding="utf-8"))
    if prereg["status"] != "ACQUISITION_ONLY_HASH_PENDING":
        raise RuntimeError("Acquisition-only runner requires HASH_PENDING preregistration")
    if prereg["evaluation_permitted"] is not False:
        raise RuntimeError("Preregistration must forbid evaluation during acquisition")
    expected_name = prereg["external_holdout"]["compressed_filename"]
    if args.capture_gz.name != expected_name:
        raise RuntimeError(f"Capture filename mismatch: {args.capture_gz.name} != {expected_name}")

    compressed_sha = sha256_path(args.capture_gz)
    detail = inspect_gzip_pcap(args.capture_gz)
    header = detail["pcap_global_header"]
    expected_snaplen = int(prereg["external_holdout"]["publisher_caplen_bytes"])
    if header["snaplen"] != expected_snaplen:
        raise RuntimeError(f"Publisher caplen mismatch: {header['snaplen']} != {expected_snaplen}")
    if header["linktype"] not in (1, 101):
        raise RuntimeError(f"Unsupported MAWI linktype for preregistered adapter: {header['linktype']}")

    manifest = {
        "schema_version": "v102-acquisition.1",
        "status": "HASH_ACQUIRED_MODEL_NOT_RUN",
        "evaluation_performed": False,
        "packet_records_decoded": False,
        "graph_windows_constructed": False,
        "support_scoring_performed": False,
        "model_inference_performed": False,
        "source_url": prereg["external_holdout"]["source_url"],
        "compressed_filename": expected_name,
        "compressed_bytes": int(args.capture_gz.stat().st_size),
        "compressed_sha256": compressed_sha,
        **detail,
        "next_step": "Pin these hashes into preregistration in a new commit before any packet-record decoding or model inference."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
