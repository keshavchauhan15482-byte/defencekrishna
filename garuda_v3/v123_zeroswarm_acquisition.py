"""V123 acquisition-only freeze for the ZeroSWARM Zenodo record.

This stage downloads every preregistered PCAP, verifies publisher MD5, computes SHA-256,
and writes immutable acquisition metadata. It does not decode packets, fit anything, run
model inference, or access labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

RECORD_ID = 15082260
API_URL = f"https://zenodo.org/api/records/{RECORD_ID}"
BASE_FILE_URL = f"https://zenodo.org/records/{RECORD_ID}/files"


class V123AcquisitionError(RuntimeError):
    pass


def digest_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fetch_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "Garuda-V123-acquisition/1.0"})
    with urlopen(req, timeout=60) as r:
        return json.load(r)


def download(url: str, path: Path) -> None:
    req = Request(url, headers={"User-Agent": "Garuda-V123-acquisition/1.0"})
    with urlopen(req, timeout=180) as r, path.open("wb") as f:
        while True:
            block = r.read(1024 * 1024)
            if not block:
                break
            f.write(block)


def normalize_md5(value: str) -> str:
    value = str(value or "").lower().strip()
    return value.split(":", 1)[-1] if ":" in value else value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selection", required=True, type=Path)
    ap.add_argument("--download-dir", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    args = ap.parse_args()
    if args.manifest.exists():
        raise V123AcquisitionError("V123 acquisition manifest already exists and is immutable")

    selection = json.loads(args.selection.read_text())
    if selection.get("status") != "SOURCE_SELECTED_BEFORE_PACKET_DOWNLOAD":
        raise V123AcquisitionError("Selection freeze is not valid")
    if int(selection.get("record_id", -1)) != RECORD_ID:
        raise V123AcquisitionError("Record ID mismatch")
    boundary = selection.get("integrity_boundary", {})
    if any(boundary.get(k) is not False for k in (
        "packet_bytes_downloaded_before_selection",
        "packet_records_decoded_before_selection",
        "model_inference_before_selection",
        "labels_accessed",
        "external_statistics_used_for_runtime_design",
    )):
        raise V123AcquisitionError("Selection integrity boundary violated")

    expected = {x["name"]: x["md5"].lower() for x in selection["expected_files"]}
    if len(expected) != 4:
        raise V123AcquisitionError("V123 requires exactly the four publisher PCAPs")

    meta = fetch_json(API_URL)
    if int(meta.get("id", -1)) != RECORD_ID:
        raise V123AcquisitionError("Zenodo metadata identity mismatch")
    files = meta.get("files", [])
    publisher = {}
    for f in files:
        key = f.get("key") or f.get("filename")
        if key in expected:
            publisher[key] = {
                "size": int(f.get("size", -1)),
                "md5": normalize_md5(f.get("checksum", "")),
            }
    if set(publisher) != set(expected):
        raise V123AcquisitionError(f"Publisher file-set mismatch: got {sorted(publisher)}")
    for name, md5 in expected.items():
        if publisher[name]["md5"] != md5:
            raise V123AcquisitionError(f"Publisher MD5 metadata mismatch: {name}")

    args.download_dir.mkdir(parents=True, exist_ok=True)
    acquired = []
    for name in expected:
        path = args.download_dir / name
        url = f"{BASE_FILE_URL}/{quote(name, safe='')}?download=1"
        download(url, path)
        md5 = digest_file(path, "md5")
        sha256 = digest_file(path, "sha256")
        size = path.stat().st_size
        if md5 != expected[name]:
            raise V123AcquisitionError(f"Downloaded MD5 mismatch: {name}")
        if publisher[name]["size"] > 0 and size != publisher[name]["size"]:
            raise V123AcquisitionError(f"Downloaded size mismatch: {name}")
        acquired.append({
            "name": name,
            "bytes": int(size),
            "md5": md5,
            "sha256": sha256,
            "source_url": url,
        })

    manifest = {
        "schema_version": "v123-acquisition.1",
        "status": "ALL_FOUR_PCAPS_HASH_FROZEN_NO_PACKET_DECODE",
        "record_id": RECORD_ID,
        "doi": selection["doi"],
        "dataset": selection["dataset"],
        "publisher": selection["publisher"],
        "selection_rule": selection["selection_rule"],
        "files": acquired,
        "total_bytes": int(sum(x["bytes"] for x in acquired)),
        "integrity": {
            "all_selected_files_downloaded": True,
            "publisher_md5_verified": True,
            "sha256_computed_before_packet_decode": True,
            "packet_records_decoded": False,
            "model_inference_performed": False,
            "labels_accessed": False,
            "external_used_for_fit_or_thresholding": False,
        },
        "registered_runtime": selection["registered_runtime"],
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    print(json.dumps(manifest, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
