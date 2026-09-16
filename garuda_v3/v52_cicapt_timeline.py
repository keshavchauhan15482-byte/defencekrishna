"""V52 CICAPT-IIoT2024 timeline provenance and warning lead-time audit.

V52 closes a different evidence gap from V48.  V48 proves controlled unseen-family
transfer; V52 asks whether a frozen alert happened *before* an independently recorded
attack event.  The code is deliberately fail-closed:

* an Attack_info.csv source is hash-audited and schema-resolved before use;
* time-only values require an explicit date (no row-order or guessed-date fallback);
* candidate provenance events are comparison evidence only, never model inputs;
* alert timestamps after an event can never count as warnings;
* the default claim is "attack-step onset lead time".  "compromise lead time" is not
  emitted unless the source contains an explicit compromise timestamp field.

This module does not train a model and never approves automatic containment.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import zipfile
from pathlib import Path

import pandas as pd

MAX_ANNOTATION_BYTES = 10 * 1024 * 1024
ATTACK_INFO_BASENAME = "attack_info.csv"


def norm(value):
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pick_col(columns, aliases):
    mapping = {norm(c): c for c in columns}
    for alias in aliases:
        key = norm(alias)
        if key in mapping:
            return mapping[key]
    return None


def discover_attack_info(archive_path, output_dir):
    """Inspect a pinned ZIP and extract one unique Attack_info.csv without executing it."""
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
        matches = [
            i for i in zf.infolist()
            if not i.is_dir() and Path(i.filename).name.casefold() == ATTACK_INFO_BASENAME
        ]
        report = {
            "protocol": "V52 CICAPT annotation source discovery",
            "archive": {
                "filename": archive_path.name,
                "bytes": int(archive_path.stat().st_size),
                "sha256": sha256(archive_path),
            },
            "member_count": len(names),
            "members": names,
            "attack_info_matches": [i.filename for i in matches],
            "source_ready": False,
            "automatic_containment_approved": False,
        }
        if len(matches) == 1:
            info = matches[0]
            if info.file_size <= 0 or info.file_size > MAX_ANNOTATION_BYTES:
                report["blocker"] = f"Attack_info.csv size {info.file_size} outside safe audit bound"
            else:
                target = output_dir / "Attack_info.csv"
                # A basename target prevents archive path traversal.  The member is treated
                # strictly as CSV bytes; no archive content is executed.
                with zf.open(info, "r") as src, target.open("wb") as dst:
                    while True:
                        block = src.read(1024 * 1024)
                        if not block:
                            break
                        dst.write(block)
                report["source_ready"] = True
                report["attack_info"] = {
                    "archive_member": info.filename,
                    "bytes": int(target.stat().st_size),
                    "sha256": sha256(target),
                    "path": str(target),
                }
        elif not matches:
            report["blocker"] = "Pinned provenance mirror does not contain Attack_info.csv"
        else:
            report["blocker"] = "Multiple Attack_info.csv members found; source identity is ambiguous"
    (output_dir / "discovery.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def resolve_attack_info_schema(df):
    time_col = pick_col(df.columns, [
        "attack_time", "attack time", "timestamp", "event_time", "event time",
        "start_time", "start time", "execution_time", "execution time", "time",
    ])
    tactic_col = pick_col(df.columns, [
        "category", "tactic", "attack_category", "attack category", "stage", "phase",
    ])
    technique_col = pick_col(df.columns, [
        "technique", "technique_id", "technique id", "ability", "ability_name", "ability name",
    ])
    pid_col = pick_col(df.columns, ["pid", "process_id", "process id"])
    status_col = pick_col(df.columns, ["status", "result", "success", "outcome"])
    compromise_col = pick_col(df.columns, [
        "compromise_time", "compromise time", "breach_time", "breach time",
        "successful_compromise_time", "successful compromise time",
    ])
    if time_col is None:
        raise ValueError(f"No attack event timestamp column found in {list(df.columns)}")
    if tactic_col is None and technique_col is None:
        raise ValueError("Attack_info.csv lacks both tactic/category and technique identity")
    return {
        "time": time_col,
        "tactic": tactic_col,
        "technique": technique_col,
        "pid": pid_col,
        "status": status_col,
        "compromise_time": compromise_col,
    }


def _parse_time_series(series, event_date=None):
    text = series.astype(str).str.strip()
    # First accept real datetimes/epochs with an independently encoded date.
    numeric = pd.to_numeric(series, errors="coerce")
    if float(numeric.notna().mean()) >= 0.95:
        med = float(numeric.dropna().median())
        if med > 1e8:
            unit = "ms" if med > 1e11 else "s"
            dt = pd.to_datetime(numeric, unit=unit, errors="coerce", utc=True)
            if float(dt.notna().mean()) >= 0.95:
                return dt, f"epoch_{unit}"
    dt = pd.to_datetime(text, errors="coerce", utc=True)
    has_date_token = text.str.contains(r"(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{4})", regex=True)
    if float(dt.notna().mean()) >= 0.95 and bool(has_date_token.mean() >= 0.95):
        return dt, "datetime_text"

    # Time-of-day is useful only if the caller supplies the campaign date explicitly.
    if event_date is None:
        raise ValueError("Attack timestamps are time-only/ambiguous; explicit --event-date is required")
    base = pd.to_datetime(str(event_date), errors="raise", utc=True).normalize()
    seconds = []
    pattern = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?$")
    for value in text:
        m = pattern.match(value)
        if not m:
            seconds.append(math.nan)
            continue
        hh, mm, ss = map(int, m.group(1, 2, 3))
        if hh > 23 or mm > 59 or ss > 59:
            seconds.append(math.nan)
            continue
        frac = float("0." + m.group(4)) if m.group(4) else 0.0
        seconds.append(hh * 3600 + mm * 60 + ss + frac)
    sec = pd.Series(seconds, index=series.index, dtype=float)
    if float(sec.notna().mean()) < 0.95:
        raise ValueError("Attack timestamp parse coverage <95%; guessing refused")
    return base + pd.to_timedelta(sec, unit="s"), "time_of_day_plus_explicit_date"


def canonical_label(value):
    return " ".join(str(value).replace("_", " ").strip().casefold().split())


def audit_attack_info(path, output_dir, candidate_timeline=None, event_date=None, tolerance_seconds=180):
    path = Path(path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(path, low_memory=False)
    if df.empty:
        raise ValueError("Attack_info.csv is empty")
    schema = resolve_attack_info_schema(df)
    dt, time_method = _parse_time_series(df[schema["time"]], event_date=event_date)
    valid = dt.notna()
    if float(valid.mean()) < 0.95:
        raise ValueError("Attack event timestamp coverage <95%")

    events = []
    for idx in df.index[valid]:
        tactic = canonical_label(df.at[idx, schema["tactic"]]) if schema["tactic"] else None
        technique = str(df.at[idx, schema["technique"]]).strip() if schema["technique"] else None
        status = str(df.at[idx, schema["status"]]).strip() if schema["status"] else None
        events.append({
            "row": int(idx),
            "epoch": float(dt.loc[idx].timestamp()),
            "timestamp_utc": dt.loc[idx].isoformat(),
            "tactic": tactic,
            "technique": technique,
            "pid": str(df.at[idx, schema["pid"]]).strip() if schema["pid"] else None,
            "status": status,
        })
    events.sort(key=lambda x: (x["epoch"], x["row"]))

    comparison = None
    if candidate_timeline:
        candidate = json.loads(Path(candidate_timeline).read_text())
        candidate_events = candidate.get("events", [])
        # Compare unique candidate (epoch, stage) pairs to the closest source event.
        unique = {}
        for row in candidate_events:
            if "epoch" not in row:
                continue
            key = (round(float(row["epoch"]), 3), canonical_label(row.get("publisher_stage", "")))
            unique[key] = row
        matches = []
        for (epoch, stage), _ in sorted(unique.items()):
            nearest = None
            for source in events:
                delta = abs(source["epoch"] - epoch)
                label_match = not stage or not source["tactic"] or stage == source["tactic"]
                rank = (0 if label_match else 1, delta)
                if nearest is None or rank < nearest[0]:
                    nearest = (rank, source)
            ok = bool(nearest and nearest[0][1] <= tolerance_seconds and nearest[0][0] == 0)
            matches.append({
                "candidate_epoch": epoch,
                "candidate_stage": stage,
                "matched": ok,
                "delta_seconds": float(nearest[0][1]) if nearest else None,
                "source_row": int(nearest[1]["row"]) if nearest else None,
                "source_tactic": nearest[1]["tactic"] if nearest else None,
            })
        comparison = {
            "candidate_file": Path(candidate_timeline).name,
            "candidate_sha256": sha256(candidate_timeline),
            "tolerance_seconds": int(tolerance_seconds),
            "rows": matches,
            "matched": int(sum(1 for r in matches if r["matched"])),
            "total": len(matches),
            "all_matched": bool(matches and all(r["matched"] for r in matches)),
        }

    explicit_compromise = schema["compromise_time"] is not None
    report = {
        "protocol": "V52 CICAPT Attack_info provenance audit",
        "source": {
            "filename": path.name,
            "bytes": int(path.stat().st_size),
            "sha256": sha256(path),
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
        },
        "schema": schema,
        "time_method": time_method,
        "event_count": len(events),
        "first_event_utc": events[0]["timestamp_utc"] if events else None,
        "last_event_utc": events[-1]["timestamp_utc"] if events else None,
        "events": events,
        "candidate_comparison": comparison,
        "explicit_compromise_timestamp_present": explicit_compromise,
        "lead_time_claim_level": "compromise_timestamp_available_for_separate_verification" if explicit_compromise else "attack_step_onset_only",
        "verified_compromise_lead_time_supported": False,
        "automatic_containment_approved": False,
    }
    (output_dir / "timeline_audit.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def _read_alerts(path):
    df = pd.read_csv(path, low_memory=False)
    time_col = pick_col(df.columns, ["timestamp", "time", "alert_time", "alert time", "ts"])
    alert_col = pick_col(df.columns, ["alert", "is_alert", "is alert", "prediction", "predicted_alert"])
    score_col = pick_col(df.columns, ["score", "risk", "risk_score", "risk score", "probability"])
    if time_col is None:
        raise ValueError("Alert file lacks timestamp")
    dt, _ = _parse_time_series(df[time_col])
    if alert_col:
        active = pd.to_numeric(df[alert_col], errors="coerce").fillna(0).astype(float) > 0
    elif score_col:
        raise ValueError("Score-only alert file requires an explicit frozen alert decision column")
    else:
        raise ValueError("Alert file lacks explicit alert decision")
    return sorted(float(x.timestamp()) for x in dt[active & dt.notna()])


def evaluate_warning_lead_time(timeline_audit, alerts_csv, output_dir, lookback_minutes=60, clean_history_minutes=8):
    timeline = json.loads(Path(timeline_audit).read_text())
    alerts = _read_alerts(alerts_csv)
    events = timeline.get("events", [])
    lookback = float(lookback_minutes) * 60.0
    clean_window = float(clean_history_minutes) * 60.0
    rows = []
    previous_event = None
    for event in events:
        epoch = float(event["epoch"])
        timeline_clean = previous_event is None or (epoch - float(previous_event)) >= clean_window
        candidates = [a for a in alerts if epoch - lookback <= a < epoch]
        first = min(candidates) if candidates else None
        rows.append({
            "event_row": event["row"],
            "event_timestamp_utc": event["timestamp_utc"],
            "tactic": event.get("tactic"),
            "technique": event.get("technique"),
            "timeline_clean_history": bool(timeline_clean),
            "warning_before_event": first is not None,
            "first_warning_epoch": first,
            "lead_seconds": (epoch - first) if first is not None else None,
        })
        previous_event = epoch
    clean_rows = [r for r in rows if r["timeline_clean_history"]]
    hit = [r for r in clean_rows if r["warning_before_event"]]
    report = {
        "protocol": "V52 frozen-alert warning-before-attack-step audit",
        "claim_boundary": "Lead time is relative to independently logged attack-step onset, not successful compromise, unless a separately verified compromise timestamp is supplied.",
        "timeline_audit_sha256": sha256(timeline_audit),
        "alerts_sha256": sha256(alerts_csv),
        "lookback_minutes": float(lookback_minutes),
        "clean_history_minutes": float(clean_history_minutes),
        "events": rows,
        "timeline_clean_event_count": len(clean_rows),
        "timeline_clean_warning_hits": len(hit),
        "timeline_clean_event_recall": (len(hit) / len(clean_rows)) if clean_rows else None,
        "positive_lead_seconds": [r["lead_seconds"] for r in hit],
        "verified_compromise_lead_time_supported": False,
        "automatic_containment_approved": False,
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "lead_time.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover")
    p.add_argument("--archive", required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("audit")
    p.add_argument("--attack-info", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--candidate-timeline")
    p.add_argument("--event-date")
    p.add_argument("--tolerance-seconds", type=int, default=180)

    p = sub.add_parser("leadtime")
    p.add_argument("--timeline-audit", required=True)
    p.add_argument("--alerts", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--lookback-minutes", type=float, default=60)
    p.add_argument("--clean-history-minutes", type=float, default=8)

    args = parser.parse_args()
    if args.command == "discover":
        result = discover_attack_info(args.archive, args.output)
    elif args.command == "audit":
        result = audit_attack_info(
            args.attack_info, args.output, args.candidate_timeline,
            event_date=args.event_date, tolerance_seconds=args.tolerance_seconds,
        )
    else:
        result = evaluate_warning_lead_time(
            args.timeline_audit, args.alerts, args.output,
            lookback_minutes=args.lookback_minutes,
            clean_history_minutes=args.clean_history_minutes,
        )
    print(json.dumps(result, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
