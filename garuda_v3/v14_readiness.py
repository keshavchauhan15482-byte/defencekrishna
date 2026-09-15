"""Fail-closed readiness check for verified independent campaign evidence."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable

from .verified_campaigns import clean_history_eligible, load_manifest, validate_manifest, verified_compromise_epoch

DEFAULT_TARGETS = {
    "calibration": {"attack": 10, "benign": 10},
    "policy": {"attack": 10, "benign": 10},
    "final_test": {"attack": 20, "benign": 20},
}


def campaign_kind(m: Dict[str, Any]) -> str:
    return "attack" if verified_compromise_epoch(m) is not None or any(e.get("outcome") == "success" for e in m["events"]) else "benign"


def evaluate(manifests: Iterable[Dict[str, Any]], split: Dict[str, list[str]] | None = None, history_minutes: int = 8) -> Dict[str, Any]:
    ms = [validate_manifest(m) for m in manifests]
    if not ms:
        return {"ready": False, "reason": "No verified campaign manifests found", "required_history_minutes": history_minutes, "counts": {}}
    by_id = {m["campaign_id"]: m for m in ms}
    if len(by_id) != len(ms):
        return {"ready": False, "reason": "Duplicate campaign IDs", "required_history_minutes": history_minutes, "counts": {}}
    if split is None:
        split = {k: [m["campaign_id"] for m in ms if m.get("role") == k] for k in ("train", "calibration", "policy", "final_test")}
    flat = [x for part in split.values() for x in part]
    if len(flat) != len(set(flat)) or any(x not in by_id for x in flat):
        return {"ready": False, "reason": "Campaign split overlap or unknown campaign", "required_history_minutes": history_minutes, "counts": {}}
    counts = {}
    reasons = []
    for part in ("calibration", "policy", "final_test"):
        c = Counter(campaign_kind(by_id[x]) for x in split.get(part, []))
        counts[part] = {"attack": c["attack"], "benign": c["benign"]}
        target = DEFAULT_TARGETS[part]
        for kind in ("attack", "benign"):
            if c[kind] < target[kind]:
                reasons.append(f"{part} has {c[kind]} {kind} campaigns; needs {target[kind]}")
    clean_attack_histories = 0
    for m in ms:
        t = verified_compromise_epoch(m)
        if t is not None and clean_history_eligible(m, t, history_minutes):
            clean_attack_histories += 1
    return {
        "ready": not reasons,
        "reason": "ready" if not reasons else "; ".join(reasons),
        "required_history_minutes": history_minutes,
        "counts": counts,
        "verified_clean_history_attack_campaigns": clean_attack_histories,
        "automatic_containment_approved": False,
        "note": "Readiness counts support evaluation design only; they do not themselves approve containment.",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest-dir", default="datasets/verified_campaigns/manifests")
    p.add_argument("--split", default="datasets/verified_campaigns/split.json")
    p.add_argument("--output", default="datasets/v14/readiness.json")
    args = p.parse_args()
    manifest_dir = Path(args.manifest_dir)
    files = sorted(manifest_dir.glob("*.json")) if manifest_dir.exists() else []
    manifests = [load_manifest(x) for x in files]
    split = None
    sp = Path(args.split)
    if sp.exists():
        raw = json.loads(sp.read_text())
        split = raw.get("assignment", raw)
    result = evaluate(manifests, split)
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    if not result["ready"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
