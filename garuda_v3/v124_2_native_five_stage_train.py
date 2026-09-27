"""V124.2 exact-native five-stage certification with publisher-native source pooling.

This is a development iteration after V124.1 failed minority-stage recall. It does not
rewrite the immutable V124.1 result. Only exact publisher-native MITRE tactic labels are
used; no proxy mapping is allowed. Source pools are fixed in code before metrics.
Per-stage rows are deduplicated, timestamp-sorted, and split 60/20/20 chronologically.
Model-family selection is validation-only; final test is evaluated once after selection.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import urllib.request
from pathlib import Path

import numpy as np

STAGES = [
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
]

SOURCES = {
    "Reconnaissance": [
        "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Reconnaissance/part-00000-ae3fd4d9-9aba-4c1d-968c-88755355ee78-c000.csv",
    ],
    "Initial Access": [
        "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Initial_Access/part-00000-e6022464-fb77-4508-a850-006424f5de8a-c000.csv",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Initial_Access/part-00000-9a37b839-429e-444b-82a5-a6d5e69dad7e-c000.csv",
    ],
    "Lateral Movement": [
        "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Lateral_Movement/part-00000-0d012414-989a-4b0f-937d-36b02cacf398-c000.csv",
        "https://datasets.uwf.edu/data/UWF-ZeekDataSum25-1/csv/Lateral_Movement/part-00000-4890c258-40e8-4ef8-b345-06d436539b95-c000.csv",
    ],
    "Command and Control": [
        "https://datasets.uwf.edu/data/UWF-ZeekDataFall22/csv/Command_and_Control/part-00000-c365ae06-4940-4fb1-b261-3a9ed9970961-c000.csv",
        "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Command_and_Control/part-00000-eac46840-7128-467c-b661-98cb0893dbae-c000.csv",
    ],
    "Exfiltration": [
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Exfiltration/part-00000-6a530c25-0f6b-46a1-ba16-c6b658ef75e8-c000.csv",
    ],
}

FEATURES = [
    "duration", "missed_bytes", "orig_bytes", "orig_ip_bytes", "orig_pkts",
    "resp_bytes", "resp_ip_bytes", "resp_pkts", "src_port_zeek", "dest_port_zeek",
]
MIN_ROWS = 15


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def norm_stage(value: str) -> str:
    return str(value).strip().replace("_", " ").lower()


def fnum(value) -> float:
    try:
        x = float(value)
        return x if np.isfinite(x) else 0.0
    except Exception:
        return 0.0


def vectorize(row: dict) -> list[float]:
    x = [fnum(row.get(k, "")) for k in FEATURES]
    proto = str(row.get("proto", "")).lower()
    service = str(row.get("service", "")).lower()
    conn_state = str(row.get("conn_state", "")).upper()
    x += [
        float(proto == "tcp"), float(proto == "udp"),
        float(service == "http"), float(service == "ftp"), float(service == "smb"),
        float(service == "dns"), float(service == "ssh"),
        float(conn_state == "SF"), float(conn_state.startswith("S")), float("R" in conn_state),
    ]
    return x


def load_pool(stage: str, urls: list[str], root: Path):
    rows = []
    files = []
    for idx, url in enumerate(urls):
        path = root / f"{stage.lower().replace(' ', '_')}_{idx}.csv"
        req = urllib.request.Request(url, headers={"User-Agent": "Garuda-V124.2/1.0"})
        with urllib.request.urlopen(req, timeout=180) as r, path.open("wb") as w:
            w.write(r.read())
        local_rows = 0
        with path.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                if norm_stage(row.get("label_tactic", "")) != stage.lower():
                    raise RuntimeError(
                        f"native label mismatch for {stage}: {row.get('label_tactic')} from {url}"
                    )
                ts = fnum(row.get("ts", "0"))
                vec = vectorize(row)
                rows.append((ts, vec))
                local_rows += 1
        files.append({"url": url, "rows": local_rows, "sha256": sha256(path)})

    # Deduplicate exact repeated observations across publisher exports.
    dedup = {}
    for ts, vec in rows:
        key = (round(ts, 6), tuple(round(v, 9) for v in vec))
        dedup[key] = (ts, vec)
    rows = sorted(dedup.values(), key=lambda z: z[0])
    return files, rows


def class_metrics(y, pred):
    out, recalls = {}, []
    for i, stage in enumerate(STAGES):
        tp = int(np.sum((y == i) & (pred == i)))
        fn = int(np.sum((y == i) & (pred != i)))
        fp = int(np.sum((y != i) & (pred == i)))
        support = int(np.sum(y == i))
        recall = tp / (tp + fn) if tp + fn else 0.0
        precision = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[stage] = {
            "support": support, "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
        }
        recalls.append(recall)
    return {
        "accuracy": float(np.mean(y == pred)),
        "macro_recall": float(np.mean(recalls)),
        "per_stage": out,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("immutable V124.2 result already exists")

    root = args.output.parent / "sources_v124_2"
    root.mkdir(parents=True, exist_ok=True)
    Xtr, ytr, Xv, yv, Xt, yt = [], [], [], [], [], []
    source = {}

    for class_id, stage in enumerate(STAGES):
        files, rows = load_pool(stage, SOURCES[stage], root)
        n = len(rows)
        if n < MIN_ROWS:
            raise RuntimeError(f"{stage} has only {n} pooled native rows; need {MIN_ROWS}")
        a = max(1, int(n * 0.60))
        b = min(max(a + 1, int(n * 0.80)), n - 1)
        parts = [rows[:a], rows[a:b], rows[b:]]
        if min(map(len, parts)) < 2:
            raise RuntimeError(f"{stage} split too small: {[len(x) for x in parts]}")
        for arr, XX, yy in zip(parts, [Xtr, Xv, Xt], [ytr, yv, yt]):
            XX.extend([r[1] for r in arr])
            yy.extend([class_id] * len(arr))
        source[stage] = {
            "files": files,
            "pooled_unique_rows": n,
            "train": len(parts[0]),
            "validation": len(parts[1]),
            "test": len(parts[2]),
        }

    Xtr, Xv, Xt = map(lambda x: np.asarray(x, float), [Xtr, Xv, Xt])
    ytr, yv, yt = map(np.asarray, [ytr, yv, yt])

    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    seed = 20260927
    candidates = {
        "logistic_balanced": Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=4000, class_weight="balanced", C=0.5, random_state=seed)),
        ]),
        "extra_trees_balanced": ExtraTreesClassifier(
            n_estimators=600, max_features="sqrt", min_samples_leaf=1,
            class_weight="balanced", random_state=seed, n_jobs=2,
        ),
        "random_forest_balanced": RandomForestClassifier(
            n_estimators=600, max_features="sqrt", min_samples_leaf=1,
            class_weight="balanced_subsample", random_state=seed, n_jobs=2,
        ),
    }

    validation = []
    for name, model in candidates.items():
        model.fit(Xtr, ytr)
        m = class_metrics(yv, model.predict(Xv))
        validation.append((m["macro_recall"], m["accuracy"], name, m))
    validation.sort(reverse=True)
    winner = validation[0][2]

    # Freeze winner from validation only, then refit on train+validation and score test once.
    model = candidates[winner]
    model.fit(np.vstack([Xtr, Xv]), np.concatenate([ytr, yv]))
    test = class_metrics(yt, model.predict(Xt))

    gates = {
        "all_exact_native_labels_no_proxy": True,
        "all_stage_source_rows_at_least_15": all(v["pooled_unique_rows"] >= MIN_ROWS for v in source.values()),
        "all_stage_test_support_at_least_3": all(v["support"] >= 3 for v in test["per_stage"].values()),
        "test_macro_recall_at_least_0_60": test["macro_recall"] >= 0.60,
        "each_stage_recall_at_least_0_40": all(v["recall"] >= 0.40 for v in test["per_stage"].values()),
    }

    result = {
        "schema_version": "v124-five-stage.2",
        "status": "PASS" if all(gates.values()) else "FAIL",
        "development_iteration": True,
        "supersedes_v124_1": False,
        "proxy_mapping_used": False,
        "stages": STAGES,
        "network_features": FEATURES + [
            "proto_tcp", "proto_udp", "service_http", "service_ftp", "service_smb",
            "service_dns", "service_ssh", "conn_state_sf", "conn_state_syn_family", "conn_state_reset_family",
        ],
        "source": source,
        "selection": {
            "split": "per-class pooled-deduplicated chronological 60/20/20",
            "selection_scope": "validation_only",
            "validation_candidates": [
                {"name": name, "macro_recall": mr, "accuracy": acc, "per_stage": mm["per_stage"]}
                for mr, acc, name, mm in validation
            ],
            "winner": winner,
        },
        "test": test,
        "gates": gates,
        "claim_boundary": (
            "Publisher-native five-stage network-record classifier development evidence with no proxy mapping. "
            "V124.1 remains immutable. This artifact does not claim successful-compromise lead time or external one-shot stage generalisation."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
