"""Verify archived V15 evidence sources still match SOURCE_SHA256.txt."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path) -> dict:
    manifest = root / "SOURCE_SHA256.txt"
    checked = {}
    for raw in manifest.read_text().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        expected, rel = raw.split(None, 1)
        path = Path(rel)
        if not path.exists():
            raise ValueError(f"Archived V15 source missing: {rel}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(f"Archived V15 provenance mismatch: {rel}: {actual} != {expected}")
        checked[rel] = actual
    if not checked:
        raise ValueError("Empty V15 source hash manifest")
    return checked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="garuda_v3/experiments/v15")
    args = parser.parse_args()
    checked = verify(Path(args.root))
    print("V15_PROVENANCE_OK", len(checked))


if __name__ == "__main__":
    main()
