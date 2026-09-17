from __future__ import annotations

"""V40 support-only audit for X-IIoTID attack-stage progression.

No model is trained and no threshold is selected.  Stage labels are used only
as temporal annotations to answer whether an honest V41 experiment is supported:
can eight minutes containing only benign / Reconnaissance / Weaponisation state
be followed by Exploitation-or-later within the next four minutes?
"""

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
OUT = HERE / "artifacts" / "xiiotid_stage_progression_audit"
OUT.mkdir(parents=True, exist_ok=True)

HANDLE = "munaalhawawreh/xiiotid-iiot-intrusion-dataset"
EXPECTED_SHA = "7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0"
EXPECTED_BYTES = 355_308_902
HISTORY = 8
HORIZON = 4
EMBARGO = (HISTORY + HORIZON) * 60

BENIGN = {"normal", "benign", "background", "0", "none"}
EARLY = {"reconnaissance", "recon", "weaponisation", "weaponization"}
LATER = {
    "exploitation", "lateralmovement", "commandandcontrol", "commandcontrol", "c2",
    "exfiltration", "tampering", "cryptoransomware", "cryptoransom", "rdos",
}
CANONICAL = {
    "normal": "Normal", "benign": "Normal", "background": "Normal", "0": "Normal", "none": "Normal",
    "reconnaissance": "Reconnaissance", "recon": "Reconnaissance",
    "weaponisation": "Weaponisation", "weaponization": "Weaponisation",
    "exploitation": "Exploitation",
    "lateralmovement": "Lateral Movement",
    "commandandcontrol": "C2", "commandcontrol": "C2", "c2": "C2",
    "exfiltration": "Exfiltration",
    "tampering": "Tampering",
    "cryptoransomware": "Crypto-ransomware", "cryptoransom": "Crypto-ransomware",
    "rdos": "RDoS",
}
EARLY_CANON = {"Reconnaissance", "Weaponisation"}
LATER_CANON = {"Exploitation", "Lateral Movement", "C2", "Exfiltration", "Tampering", "Crypto-ransomware", "RDoS"}
ALLOWED_HISTORY = {"Normal"} | EARLY_CANON
KNOWN = ALLOWED_HISTORY | LATER_CANON


def norm(v) -> str:
    return "".join(ch.lower() for ch in str(v).strip() if ch.isalnum())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def pick_col(cols, names):
    m = {norm(c): c for c in cols}
    for name in names:
        if norm(name) in m:
            return m[norm(name)]
    return None


def canonical_stage(v):
    return CANONICAL.get(norm(v))


def stage_column(sample: pd.DataFrame):
    preferred_names = ["class2", "attack_stage", "attackstage", "stage", "phase"]
    candidates = []
    preferred = {norm(x) for x in preferred_names}
    for c in sample.columns:
        nc = norm(c)
        if nc in preferred or any(k in nc for k in ("class", "stage", "phase", "attack")):
            vals = sample[c].dropna().astype(str)
            if vals.empty:
                continue
            mapped = vals.map(canonical_stage)
            known_n = int(mapped.notna().sum())
            distinct = sorted(set(mapped.dropna().astype(str)))
            known_fraction = float(known_n / len(vals))
            # Reward exact/preferred stage-like names and broad stage coverage.
            name_bonus = 1 if nc in preferred else 0
            score = (name_bonus, len(distinct), known_fraction, known_n)
            candidates.append({
                "column": c, "score": score, "known_fraction": known_fraction,
                "known_rows": known_n, "mapped_stages": distinct,
                "top_raw_values": vals.value_counts().head(20).index.astype(str).tolist(),
            })
    if not candidates:
        raise RuntimeError("No stage-label candidate column found")
    candidates.sort(key=lambda r: r["score"], reverse=True)
    chosen = candidates[0]
    if len(chosen["mapped_stages"]) < 4 or chosen["known_fraction"] < 0.50:
        raise RuntimeError(f"No trustworthy stage column: {candidates[:8]}")
    clean = []
    for r in candidates:
        x = dict(r); x["score"] = list(x["score"]); clean.append(x)
    return chosen["column"], clean


def parse_time(df: pd.DataFrame, date_col, ts_col):
    attempts = []
    if date_col and date_col != ts_col:
        attempts.append(("date+timestamp", df[date_col].astype(str).str.strip() + " " + df[ts_col].astype(str).str.strip()))
    attempts.append(("timestamp", df[ts_col]))
    for name, s in attempts:
        dt = pd.to_datetime(s.astype(str), errors="coerce", utc=True)
        frac = float(dt.notna().mean())
        if frac >= 0.80:
            return dt, name, frac
        num = pd.to_numeric(s, errors="coerce")
        if float(num.notna().mean()) >= 0.80:
            med = float(num.dropna().median())
            unit = "ms" if med > 1e11 else "s"
            dt = pd.to_datetime(num, unit=unit, errors="coerce", utc=True)
            frac = float(dt.notna().mean())
            if frac >= 0.80:
                return dt, name + ":" + unit, frac
    raise RuntimeError("timestamp parsing below 80%")


def split_masks(cutoff: np.ndarray):
    unique = np.unique(cutoff)
    if len(unique) < 40:
        raise RuntimeError(f"only {len(unique)} unique cutoff times")
    b1 = unique[int(.60 * (len(unique) - 1))]
    b2 = unique[int(.75 * (len(unique) - 1))]
    b3 = unique[int(.85 * (len(unique) - 1))]
    return {
        "train": cutoff <= b1,
        "calibration": (cutoff > b1 + EMBARGO) & (cutoff <= b2),
        "policy": (cutoff > b2 + EMBARGO) & (cutoff <= b3),
        "test": cutoff > b3 + EMBARGO,
    }, {"train_end": int(b1), "calibration_end": int(b2), "policy_end": int(b3), "embargo_seconds": EMBARGO}


def first_later(future_sets, cutoff, minute_times):
    for j, stages in enumerate(future_sets):
        hits = sorted(set(stages) & LATER_CANON)
        if hits:
            lead = int(minute_times[j] - cutoff)
            return hits, lead
    return [], None


def build_sequences(minute_table: dict[str, list[tuple[int, frozenset[str]]]]):
    rows = []
    transition_pairs = Counter()
    positive_entities = set()
    for entity, seq in minute_table.items():
        seq = sorted(seq)
        t = np.asarray([x[0] for x in seq], dtype=np.int64)
        stages = [x[1] for x in seq]
        for i in range(HISTORY - 1, len(seq) - HORIZON):
            lo = i - HISTORY + 1
            span = t[lo:i + HORIZON + 1]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            hist = stages[lo:i + 1]
            fut = stages[i + 1:i + HORIZON + 1]
            all_sets = hist + fut
            # Any unmapped stage in any minute invalidates the support label.
            if any((not s) or (not set(s).issubset(KNOWN)) for s in all_sets):
                continue
            if any(not set(s).issubset(ALLOWED_HISTORY) for s in hist):
                continue
            observed = sorted(set().union(*hist) & EARLY_CANON)
            future_union = set().union(*fut)
            if future_union & LATER_CANON:
                target = 1
            elif future_union.issubset(ALLOWED_HISTORY):
                target = 0
            else:
                continue
            cutoff = int(t[i])
            later_stages, lead = first_later(fut, cutoff, t[i + 1:i + HORIZON + 1])
            if target == 1 and not later_stages:
                raise RuntimeError("positive sequence without later-stage lead")
            if target == 1 and observed:
                positive_entities.add(entity)
                for a in observed:
                    for b in later_stages:
                        transition_pairs[(a, b)] += 1
            rows.append({
                "entity": entity,
                "cutoff": cutoff,
                "target": int(target),
                "observed_early": bool(observed),
                "observed_early_stages": observed,
                "future_later_stages": later_stages,
                "lead_seconds": lead,
            })
    if not rows:
        raise RuntimeError("no eligible progression sequences")
    return rows, positive_entities, transition_pairs


def support(rows, mask):
    rr = [r for r, keep in zip(rows, mask) if keep]
    obs = [r for r in rr if r["observed_early"]]
    pos = [r for r in obs if r["target"] == 1]
    neg = [r for r in obs if r["target"] == 0]
    broad_pos = [r for r in rr if r["target"] == 1]
    broad_neg = [r for r in rr if r["target"] == 0]
    return {
        "eligible_all_n": len(rr),
        "eligible_all_positive_n": len(broad_pos),
        "eligible_all_negative_n": len(broad_neg),
        "observed_early_n": len(obs),
        "observed_early_positive_n": len(pos),
        "observed_early_negative_n": len(neg),
        "observed_early_positive_entities": len(set(r["entity"] for r in pos)),
        "positive_lead_seconds": {
            "n": len(pos),
            "min": int(min(r["lead_seconds"] for r in pos)) if pos else None,
            "median": float(np.median([r["lead_seconds"] for r in pos])) if pos else None,
            "max": int(max(r["lead_seconds"] for r in pos)) if pos else None,
        },
    }


def main():
    import kagglehub

    root = Path(kagglehub.dataset_download(HANDLE))
    csvs = list(root.rglob("*.csv"))
    if not csvs:
        raise RuntimeError("No CSV found in X-IIoTID package")
    csv_path = max(csvs, key=lambda p: p.stat().st_size)
    actual_sha = sha256(csv_path); actual_bytes = int(csv_path.stat().st_size)
    if actual_sha != EXPECTED_SHA or actual_bytes != EXPECTED_BYTES:
        raise RuntimeError(f"X-IIoTID provenance mismatch sha={actual_sha} bytes={actual_bytes}")

    sample = pd.read_csv(csv_path, nrows=120_000, low_memory=False)
    stage_col, stage_candidates = stage_column(sample)
    date_col = pick_col(sample.columns, ["Date"])
    ts_col = pick_col(sample.columns, ["Timestamp", "Ts", "Time"])
    src_col = pick_col(sample.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    if ts_col is None:
        raise RuntimeError("No timestamp column")
    usecols = list(dict.fromkeys(c for c in (date_col, ts_col, src_col, stage_col) if c))
    df = pd.read_csv(csv_path, usecols=usecols, low_memory=False)
    dt, time_method, parsed_fraction = parse_time(df, date_col, ts_col)
    stage = df[stage_col].map(canonical_stage)
    raw_stage = df[stage_col].astype(str)
    entity = df[src_col].astype(str) if src_col else pd.Series("GLOBAL", index=df.index)

    base = pd.DataFrame({"dt": dt, "entity": entity, "stage": stage, "raw_stage": raw_stage})
    base = base.dropna(subset=["dt"]).copy()
    base["minute"] = (base["dt"].astype("int64") // 10**9 // 60 * 60).astype("int64")

    raw_counts = raw_stage.value_counts().head(50).to_dict()
    mapped_counts = Counter(x for x in stage.dropna().astype(str))
    unmapped = base[base["stage"].isna()]["raw_stage"].value_counts().head(30).to_dict()

    # Preserve unknownness at minute level by inserting an explicit sentinel.
    base["stage_token"] = base["stage"].fillna("__UNMAPPED__")
    grouped = base.groupby(["entity", "minute"], sort=True)["stage_token"].agg(lambda s: frozenset(s.astype(str)))
    minute_table = defaultdict(list)
    for (ent, minute), stages in grouped.items():
        minute_table[str(ent)].append((int(minute), stages))

    rows, positive_entities, transition_pairs = build_sequences(minute_table)
    cutoffs = np.asarray([r["cutoff"] for r in rows], dtype=np.int64)
    masks, boundaries = split_masks(cutoffs)
    split_support = {name: support(rows, mask) for name, mask in masks.items()}

    min_pos = {"train":50, "calibration":10, "policy":10, "test":20}
    min_neg = {"train":100, "calibration":50, "policy":50, "test":100}
    gate = {
        "positive_support_per_split_pass": all(split_support[k]["observed_early_positive_n"] >= min_pos[k] for k in min_pos),
        "negative_support_per_split_pass": all(split_support[k]["observed_early_negative_n"] >= min_neg[k] for k in min_neg),
        "positive_entity_support_pass": len(positive_entities) >= 5,
        "progression_pair_support_pass": len(transition_pairs) >= 2,
        "positive_lead_time_support_pass": any(r["observed_early"] and r["target"] == 1 and (r["lead_seconds"] or 0) > 0 for r in rows),
    }
    gate["pass"] = bool(all(gate.values()))

    report = {
        "schema": "krishna-v40-xiiotid-stage-progression-support-v1",
        "audit_only": True,
        "model_training": False,
        "threshold_selection": False,
        "provenance": {
            "dataset": "X-IIoTID", "transport_handle": HANDLE,
            "filename": csv_path.name, "bytes": actual_bytes, "sha256": actual_sha,
            "rows": int(len(df)), "columns_loaded": usecols,
        },
        "detected": {
            "stage_column": stage_col, "stage_candidates": stage_candidates,
            "timestamp_column": ts_col, "date_column": date_col, "source_entity_column": src_col,
            "time_parse_method": time_method, "time_parse_fraction": parsed_fraction,
            "mapped_stage_counts": dict(mapped_counts),
            "top_raw_stage_values": raw_counts,
            "top_unmapped_stage_values": unmapped,
            "entity_n": int(len(minute_table)),
            "minute_state_n": int(len(grouped)),
        },
        "protocol": {
            "history_minutes": HISTORY, "future_minutes": HORIZON,
            "history_allowed": sorted(ALLOWED_HISTORY), "early_precursors": sorted(EARLY_CANON),
            "progression_boundary": sorted(LATER_CANON), "chronological_boundaries": boundaries,
        },
        "sequence": {
            "eligible_n": len(rows),
            "observed_early_n": int(sum(r["observed_early"] for r in rows)),
            "observed_early_positive_n": int(sum(r["observed_early"] and r["target"] == 1 for r in rows)),
            "observed_early_negative_n": int(sum(r["observed_early"] and r["target"] == 0 for r in rows)),
            "positive_progression_entity_n": len(positive_entities),
            "progression_pairs": {f"{a} -> {b}": int(n) for (a,b), n in transition_pairs.most_common()},
        },
        "split_support": split_support,
        "v41_support_gate": gate,
        "claim_boundary": "support audit only; no forecasting accuracy claim",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary = {
        "detected_stage_column": stage_col,
        "mapped_stage_counts": dict(mapped_counts),
        "sequence": report["sequence"],
        "split_support": split_support,
        "v41_support_gate": gate,
    }
    (OUT / "REPORT.md").write_text(
        "# V40 X-IIoTID stage-progression support audit\n\n"
        "No model was trained and no threshold was selected.\n\n"
        "```json\n" + json.dumps(summary, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V40 support gate for a V41 progression model was not met")


if __name__ == "__main__":
    main()
