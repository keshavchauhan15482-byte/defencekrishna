from __future__ import annotations

"""V33 support-only audit of UNSW IoT Analytics Attack Traces.

The publisher provides separate flow-data and annotation ZIP archives. This
script downloads both, hashes them, inventories their schema, parses timestamped
attack intervals, heuristically maps annotation files to flow files by filename,
and checks whether at least eight distinct one-minute flow bins are observable
before each onset without another annotated attack overlapping that prehistory.
No forecasting model is trained and no accuracy metric is produced.
"""

import hashlib
import json
import re
import tempfile
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "artifacts" / "unsw_attacktrace_audit"
OUT.mkdir(parents=True, exist_ok=True)

SOURCES = {
    "annotations": "https://iotanalytics.unsw.edu.au/anomaly-data/annotations.zip",
    "flowdata": "https://iotanalytics.unsw.edu.au/anomaly-data/flowdata.zip",
}
MAX_FLOW_LINES_PER_FILE = 500_000
PREHISTORY_SECONDS = 8 * 60


def download(url: str, path: Path) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V33/1.0"})
    h = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(req, timeout=180) as r, path.open("wb") as f:
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            h.update(chunk)
            size += len(chunk)
    return {"url": url, "bytes": int(size), "sha256": h.hexdigest()}


def text_members(z: zipfile.ZipFile):
    for info in z.infolist():
        if info.is_dir():
            continue
        yield info


def normalize_epoch(x: float):
    if 1e9 <= x <= 4e9:
        return float(x)
    if 1e12 <= x <= 4e12:
        return float(x) / 1000.0
    if 1e15 <= x <= 4e15:
        return float(x) / 1_000_000.0
    return None


def numeric_epoch_from_line(line: str):
    # Search early fields first; flowtime in this corpus may be seconds or ms.
    fields = re.split(r"[,;\t\s]+", line.strip())
    for token in fields[:12]:
        try:
            val = normalize_epoch(float(token))
        except Exception:
            continue
        if val is not None:
            return val
    return None


def stem_tokens(name: str):
    stem = Path(name).stem.lower()
    toks = [t for t in re.split(r"[^a-z0-9]+", stem) if len(t) >= 3 and not t.isdigit()]
    return set(toks)


def map_annotation_to_flow(annotation_name: str, flow_names: list[str]):
    a = stem_tokens(annotation_name)
    if not a:
        return None, 0.0
    best = None
    for f in flow_names:
        b = stem_tokens(f)
        if not b:
            continue
        inter = len(a & b)
        union = len(a | b)
        score = inter / union if union else 0.0
        # Exact normalized stem containment is a strong filename signal.
        an = re.sub(r"[^a-z0-9]", "", Path(annotation_name).stem.lower())
        fn = re.sub(r"[^a-z0-9]", "", Path(f).stem.lower())
        if an and (an in fn or fn in an):
            score = max(score, 0.95)
        cand = (score, inter, f)
        if best is None or cand > best:
            best = cand
    if best is None or best[0] <= 0:
        return None, 0.0
    return best[2], float(best[0])


def parse_annotations(z: zipfile.ZipFile):
    events = []
    inventory = []
    for info in text_members(z):
        raw = z.read(info)
        text = raw.decode("utf-8", errors="ignore")
        parsed = 0
        for line_no, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split(",")]
            if len(parts) < 2:
                continue
            try:
                start = normalize_epoch(float(parts[0]))
                end = normalize_epoch(float(parts[1]))
            except Exception:
                continue
            if start is None or end is None or end < start:
                continue
            label = parts[-1] if len(parts) >= 3 else "unknown"
            impacted = parts[2] if len(parts) >= 4 else ""
            events.append({
                "annotation_file": info.filename,
                "line": int(line_no),
                "start": float(start),
                "end": float(end),
                "duration_seconds": float(end - start),
                "impacted": impacted,
                "label": label,
            })
            parsed += 1
        inventory.append({
            "name": info.filename,
            "bytes": int(info.file_size),
            "parsed_events": int(parsed),
        })
    return events, inventory


def inspect_flowdata(z: zipfile.ZipFile):
    files = {}
    inventory = []
    for info in text_members(z):
        minutes = set()
        timestamped = 0
        scanned = 0
        preview = []
        try:
            fh = z.open(info)
        except Exception:
            inventory.append({"name": info.filename, "bytes": int(info.file_size), "error": "open_failed"})
            continue
        with fh:
            for raw in fh:
                if scanned >= MAX_FLOW_LINES_PER_FILE:
                    break
                scanned += 1
                line = raw.decode("utf-8", errors="ignore").rstrip("\r\n")
                if len(preview) < 2 and line:
                    preview.append(line[:240])
                ts = numeric_epoch_from_line(line)
                if ts is not None:
                    timestamped += 1
                    minutes.add(int(ts // 60))
        row = {
            "name": info.filename,
            "bytes": int(info.file_size),
            "lines_scanned": int(scanned),
            "timestamped_lines": int(timestamped),
            "distinct_minutes": int(len(minutes)),
            "scan_truncated": bool(scanned >= MAX_FLOW_LINES_PER_FILE),
            "preview": preview,
        }
        inventory.append(row)
        files[info.filename] = {"minutes": minutes, "summary": row}
    return files, inventory


def overlaps_other_event(events, current, lo, hi):
    for e in events:
        if e is current:
            continue
        if e["annotation_file"] != current["annotation_file"]:
            continue
        if e["start"] < hi and e["end"] > lo:
            return True
    return False


def main():
    report = {
        "schema": "krishna-v33-unsw-attacktrace-support-audit-v1",
        "audit_only": True,
        "model_training": False,
        "threshold_selection": False,
        "sources": {},
    }
    with tempfile.TemporaryDirectory(prefix="krishna-v33-") as tmp:
        tmpdir = Path(tmp)
        paths = {}
        for name, url in SOURCES.items():
            path = tmpdir / f"{name}.zip"
            print(f"V33 download {name}: {url}", flush=True)
            meta = download(url, path)
            report["sources"][name] = meta
            paths[name] = path
            print(json.dumps(meta, indent=2), flush=True)

        with zipfile.ZipFile(paths["annotations"]) as za:
            events, annotation_inventory = parse_annotations(za)
        if not events:
            raise RuntimeError("No timestamped attack annotations could be parsed")

        with zipfile.ZipFile(paths["flowdata"]) as zf:
            flow_files, flow_inventory = inspect_flowdata(zf)
        if not flow_files:
            raise RuntimeError("No flow-data files could be inspected")

    flow_names = sorted(flow_files)
    by_annotation = defaultdict(list)
    for e in events:
        by_annotation[e["annotation_file"]].append(e)

    mapped_files = {}
    for ann_name in sorted(by_annotation):
        mapped, score = map_annotation_to_flow(ann_name, flow_names)
        mapped_files[ann_name] = {"flow_file": mapped, "filename_match_score": score}

    supported = 0
    mapped_events = 0
    label_counter = Counter()
    event_rows = []
    for e in events:
        label_counter[e["label"]] += 1
        mapping = mapped_files[e["annotation_file"]]
        flow_name = mapping["flow_file"]
        minutes_before = 0
        no_prior_annotated_attack = not overlaps_other_event(
            events, e, e["start"] - PREHISTORY_SECONDS, e["start"]
        )
        if flow_name and flow_name in flow_files:
            mapped_events += 1
            minute_set = flow_files[flow_name]["minutes"]
            onset_min = int(e["start"] // 60)
            required = set(range(onset_min - 8, onset_min))
            minutes_before = len(required & minute_set)
        has_8min = bool(minutes_before >= 8 and no_prior_annotated_attack)
        supported += int(has_8min)
        event_rows.append({
            **e,
            "mapped_flow_file": flow_name,
            "filename_match_score": mapping["filename_match_score"],
            "observable_distinct_minutes_in_prior_8min": int(minutes_before),
            "no_other_annotated_attack_in_prior_8min": bool(no_prior_annotated_attack),
            "clean_prehistory_support": has_8min,
        })

    durations = [e["duration_seconds"] for e in events]
    report.update({
        "annotation_inventory": annotation_inventory,
        "flow_inventory": flow_inventory,
        "mapping": mapped_files,
        "summary": {
            "annotation_file_n": int(len(annotation_inventory)),
            "flow_file_n": int(len(flow_inventory)),
            "parseable_attack_event_n": int(len(events)),
            "mapped_attack_event_n": int(mapped_events),
            "clean_8min_prehistory_supported_event_n": int(supported),
            "clean_8min_prehistory_support_fraction": float(supported / len(events)),
            "attack_label_n": int(len(label_counter)),
            "attack_labels": dict(label_counter.most_common()),
            "duration_seconds_min": float(min(durations)),
            "duration_seconds_median": float(sorted(durations)[len(durations)//2]),
            "duration_seconds_max": float(max(durations)),
        },
        "events": event_rows,
    })
    report["decision"] = {
        "suitable_for_next_clean_onset_forecasting_pilot": bool(supported >= 5 and len(label_counter) >= 2),
        "rule": "at least 5 independently annotated events with observable attack-free 8-minute prehistory and at least 2 attack labels",
    }

    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary = {"sources": report["sources"], "summary": report["summary"], "decision": report["decision"]}
    (OUT / "REPORT.md").write_text(
        "# V33 UNSW IoT Attack Traces support audit\n\n"
        "Support/provenance audit only; no forecasting model was trained.\n\n"
        "```json\n" + json.dumps(summary, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
