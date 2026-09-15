from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

OUT = Path("artifacts/source_audit")
OUT.mkdir(parents=True, exist_ok=True)

# Prefer mirrors that cite the canonical UNSW ToN-IoT collection. The audit does
# not trust labels blindly: it first verifies that a real timestamp and network
# endpoint columns are present before a source can be used for forecasting.
CANDIDATE_DATASETS = [
    "medworldmed/ton-iot-datasets",
    "arnobbhowmik/ton-iot-network-dataset",
]
TIMESTAMP_NAMES = {"ts", "timestamp", "time", "date_time", "datetime"}
SRC_NAMES = {"src_ip", "source_ip", "srcip", "id_orig_h"}
DST_NAMES = {"dst_ip", "destination_ip", "dstip", "id_resp_h"}
FAMILY_NAMES = {"type", "attack_type", "category", "attack_cat"}
LABEL_NAMES = {"label", "binary_label", "class"}


def norm(x: str) -> str:
    return str(x).strip().lower().replace("-", "_").replace(" ", "_")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_col(cols, names):
    by = {norm(c): c for c in cols}
    for n in names:
        if n in by:
            return by[n]
    return None


def parse_ts(series: pd.Series) -> pd.Series:
    num = pd.to_numeric(series, errors="coerce")
    if num.notna().mean() >= 0.95:
        med = float(num.dropna().abs().median()) if num.notna().any() else 0.0
        unit = "s"
        if med > 1e17:
            unit = "ns"
        elif med > 1e14:
            unit = "us"
        elif med > 1e11:
            unit = "ms"
        return pd.to_datetime(num, unit=unit, errors="coerce", utc=True)
    return pd.to_datetime(series.astype(str), errors="coerce", utc=True)


def audit_csv(path: Path) -> dict:
    cols = list(pd.read_csv(path, nrows=0).columns)
    ts = find_col(cols, TIMESTAMP_NAMES)
    src = find_col(cols, SRC_NAMES)
    dst = find_col(cols, DST_NAMES)
    family = find_col(cols, FAMILY_NAMES)
    label = find_col(cols, LABEL_NAMES)
    row = {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "column_count": len(cols),
        "timestamp_col": ts,
        "source_ip_col": src,
        "destination_ip_col": dst,
        "family_col": family,
        "label_col": label,
        "forecast_source_candidate": bool(ts and src and dst and family and label),
    }
    if not row["forecast_source_candidate"]:
        row["missing_for_forecast"] = [
            name
            for name, value in {
                "timestamp": ts,
                "source_ip": src,
                "destination_ip": dst,
                "family": family,
                "label": label,
            }.items()
            if not value
        ]
        return row

    use = [ts, src, dst, family, label]
    # A bounded chronology audit is enough to decide whether a mirror is usable;
    # the full V23 training run will stream the chosen source separately.
    d = pd.read_csv(path, usecols=use, nrows=500_000, low_memory=False)
    dt = parse_ts(d[ts])
    valid = dt.notna()
    row["sample_rows"] = int(len(d))
    row["timestamp_parse_rate"] = float(valid.mean())
    if valid.any():
        sec = (dt[valid].astype("int64") // 10**9).to_numpy(np.int64)
        row["sample_time_min_utc"] = str(dt[valid].min())
        row["sample_time_max_utc"] = str(dt[valid].max())
        row["sample_time_span_seconds"] = int(sec.max() - sec.min())
        row["timestamp_unique"] = int(np.unique(sec).size)
    fam = d[family].fillna("unknown").astype(str).map(norm)
    lab = pd.to_numeric(d[label], errors="coerce")
    row["sample_family_counts"] = {str(k): int(v) for k, v in fam.value_counts().head(20).items()}
    row["sample_label_counts"] = {str(k): int(v) for k, v in lab.value_counts(dropna=False).head(10).items()}
    row["source_ip_unique_sample"] = int(d[src].astype(str).nunique())
    row["destination_ip_unique_sample"] = int(d[dst].astype(str).nunique())
    row["forecast_source_candidate"] = bool(
        row["timestamp_parse_rate"] >= 0.95
        and row.get("sample_time_span_seconds", 0) >= 600
        and len(row["sample_family_counts"]) >= 2
    )
    if path.stat().st_size <= 400 * 1024 * 1024:
        row["sha256"] = sha256(path)
    return row


def main():
    import kagglehub

    report = {
        "schema": "krishna-v23-toniot-source-audit-v1",
        "purpose": "Find a timestamp-preserving strict-network ToN-IoT source for clean-history future forecasting.",
        "canonical_reference": "UNSW ToN-IoT network + SecurityEvents ground truth",
        "datasets": {},
        "viable_sources": [],
    }
    for slug in CANDIDATE_DATASETS:
        print(f"AUDIT dataset={slug}", flush=True)
        try:
            root = Path(kagglehub.dataset_download(slug))
            entries = []
            csvs = sorted(root.rglob("*.csv"), key=lambda p: p.stat().st_size, reverse=True)
            for path in csvs[:80]:
                try:
                    a = audit_csv(path)
                    entries.append(a)
                    if a.get("forecast_source_candidate"):
                        report["viable_sources"].append({"dataset": slug, **a})
                except Exception as e:
                    entries.append({"path": str(path), "size_bytes": path.stat().st_size, "error": repr(e)})
            report["datasets"][slug] = {"root": str(root), "csv_count": len(csvs), "files": entries}
        except Exception as e:
            report["datasets"][slug] = {"error": repr(e)}

    report["ready_for_v23_training"] = bool(report["viable_sources"])
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "# V23 ToN-IoT source audit",
        "",
        f"Ready for V23 training: **{report['ready_for_v23_training']}**",
        "",
        "A source is accepted only when it preserves a parseable timestamp, source/destination network endpoints, attack family, binary label, and at least ten minutes of chronology in the bounded audit sample.",
        "",
        "```json",
        json.dumps({"viable_sources": report["viable_sources"]}, indent=2),
        "```",
    ]
    (OUT / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"ready": report["ready_for_v23_training"], "viable": report["viable_sources"]}, indent=2), flush=True)
    if not report["ready_for_v23_training"]:
        raise RuntimeError("No timestamp-preserving ToN-IoT network source found in audited mirrors")


if __name__ == "__main__":
    main()
