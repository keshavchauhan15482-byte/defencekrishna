from __future__ import annotations

import csv
import json
import math
import tempfile
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "artifacts" / "unsw_schema_preflight"
OUT.mkdir(parents=True, exist_ok=True)
FLOW_URL = "https://iotanalytics.unsw.edu.au/anomaly-data/flowdata.zip"
ANN_URL = "https://iotanalytics.unsw.edu.au/anomaly-data/annotations.zip"


def download(url: str, path: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V34/1.0"})
    with urllib.request.urlopen(req, timeout=180) as r, path.open("wb") as f:
        while True:
            b = r.read(1024 * 1024)
            if not b:
                break
            f.write(b)


def norm_epoch(v: str):
    try:
        x = float(v)
    except Exception:
        return None, None
    if not math.isfinite(x):
        return None, None
    if 1e9 <= x <= 4e9:
        return x, "seconds"
    if 1e12 <= x <= 4e12:
        return x / 1000.0, "milliseconds"
    if 1e15 <= x <= 4e15:
        return x / 1_000_000.0, "microseconds"
    return None, None


def split_line(line: str, delimiter: str):
    if delimiter == "whitespace":
        return line.split()
    return next(csv.reader([line], delimiter=delimiter))


def sniff(lines: list[str]):
    sample = "\n".join(lines[:8])
    try:
        d = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        return d
    except Exception:
        counts = {d: sum(x.count(d) for x in lines[:8]) for d in [",", ";", "\t", "|"]}
        best = max(counts, key=counts.get)
        return best if counts[best] else "whitespace"


def inspect_member(z: zipfile.ZipFile, name: str):
    lines = []
    with z.open(name) as fh:
        for raw in fh:
            s = raw.decode("utf-8", errors="ignore").strip()
            if s:
                lines.append(s)
            if len(lines) >= 120:
                break
    if not lines:
        return {"name": name, "empty": True}
    delim = sniff(lines)
    rows = [split_line(x, delim) for x in lines]
    widths = Counter(len(r) for r in rows)
    width = widths.most_common(1)[0][0]
    rows = [r for r in rows if len(r) == width]

    timestamp_candidates = []
    numeric_fraction = []
    for j in range(width):
        vals = [r[j].strip() for r in rows[:100]]
        nums = 0
        epochs = []
        units = Counter()
        for v in vals:
            try:
                x = float(v)
                if math.isfinite(x):
                    nums += 1
            except Exception:
                pass
            e, u = norm_epoch(v)
            if e is not None:
                epochs.append(e)
                units[u] += 1
        numeric_fraction.append(nums / max(1, len(vals)))
        if len(epochs) >= max(3, int(0.7 * len(vals))):
            timestamp_candidates.append({
                "index": j,
                "epoch_unit": units.most_common(1)[0][0],
                "support": len(epochs),
                "min_epoch_seconds": min(epochs),
                "max_epoch_seconds": max(epochs),
            })

    first = rows[0]
    header_like = sum(1 for v in first if not _is_number(v)) > width * 0.4
    return {
        "name": name,
        "delimiter": "\\t" if delim == "\t" else delim,
        "modal_field_count": width,
        "sample_row_count": len(rows),
        "first_records": lines[:3],
        "first_row_header_like": bool(header_like),
        "numeric_fraction_by_index": numeric_fraction,
        "timestamp_candidates": timestamp_candidates,
    }


def _is_number(v: str):
    try:
        float(v)
        return True
    except Exception:
        return False


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v34-") as t:
        td = Path(t)
        fp, ap = td / "flow.zip", td / "ann.zip"
        download(FLOW_URL, fp)
        download(ANN_URL, ap)
        with zipfile.ZipFile(fp) as z:
            flow_names = [i.filename for i in z.infolist() if not i.is_dir()]
            flow = [inspect_member(z, n) for n in flow_names]
        with zipfile.ZipFile(ap) as z:
            ann_names = [i.filename for i in z.infolist() if not i.is_dir()]

    timestamp_contract = []
    width_counter = Counter()
    delimiter_counter = Counter()
    for f in flow:
        if f.get("empty"):
            continue
        width_counter[f["modal_field_count"]] += 1
        delimiter_counter[f["delimiter"]] += 1
        for c in f["timestamp_candidates"]:
            timestamp_contract.append((f["name"], c["index"], c["epoch_unit"], c["support"]))

    index_counter = Counter((x[1], x[2]) for x in timestamp_contract)
    best_ts = index_counter.most_common(1)[0] if index_counter else None
    consistent = bool(best_ts and best_ts[1] >= max(1, len(flow) // 2))
    contract = {
        "flow_file_n": len(flow),
        "annotation_file_n": len(ann_names),
        "modal_field_counts": dict(width_counter),
        "delimiters": dict(delimiter_counter),
        "best_timestamp_index_and_unit": list(best_ts[0]) if best_ts else None,
        "files_supporting_best_timestamp_contract": int(best_ts[1]) if best_ts else 0,
        "timestamp_contract_consistent": consistent,
        "model_pilot_schema_ready": consistent and bool(width_counter),
    }
    report = {
        "schema": "krishna-v34-unsw-flow-schema-preflight-v1",
        "flow_files": flow,
        "annotation_files": ann_names,
        "schema_contract": contract,
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V34 UNSW flow-schema preflight\n\n```json\n" + json.dumps(contract, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2), flush=True)
    if not contract["model_pilot_schema_ready"]:
        raise RuntimeError("UNSW flow schema contract not sufficiently consistent for pilot")


if __name__ == "__main__":
    main()
