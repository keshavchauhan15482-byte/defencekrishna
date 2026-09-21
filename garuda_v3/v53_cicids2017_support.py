"""V53 CIC-IDS2017 timestamp-preserving whole-campaign support audit.

V51 correctly refused the common MachineLearningCSV mirror because that release drops
Timestamp/identity columns. V53 runs the same fail-closed campaign-disjoint support
protocol on the original GeneratedLabelledFlows/TrafficLabelling CSV release. No model
is trained here.

Each source file is an immutable campaign. Timestamp and attack labels are used only
for chronology and evaluation truth; they are never model features.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

WINDOW_SECONDS = 10
HISTORY = 8
HORIZON = 4
BENIGN = {"benign", "normal"}
CAMPAIGN_DATES = {
    "monday": "2017-07-03",
    "tuesday": "2017-07-04",
    "wednesday": "2017-07-05",
    "thursday": "2017-07-06",
    "friday": "2017-07-07",
}


def norm(value):
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _columns(path):
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        import pyarrow.parquet as pq
        return list(pq.ParquetFile(path).schema.names)
    return list(pd.read_csv(path, nrows=0).columns)


def resolve_columns(path):
    cols = _columns(path)
    mapping = {norm(c): c for c in cols}
    ts = next((mapping[k] for k in ("timestamp", "flowstarttime", "starttime") if k in mapping), None)
    label = next((mapping[k] for k in ("label", "traffic", "class") if k in mapping), None)
    if not ts or not label:
        raise ValueError(f"Missing timestamp/label in {Path(path).name}: {cols}")
    return ts, label, len(cols)


def expected_campaign_date(path):
    name = Path(path).name.casefold()
    matches = [(day, date) for day, date in CAMPAIGN_DATES.items() if day in name]
    if len(matches) != 1:
        return None
    return matches[0][1]


def _epoch_unit(values):
    """Infer a standard Unix epoch unit from magnitude only."""
    finite = np.asarray(values, dtype=np.float64)
    finite = finite[np.isfinite(finite)]
    if not len(finite):
        return None
    magnitude = float(np.median(np.abs(finite)))
    if 1e17 <= magnitude < 1e20:
        return "ns"
    if 1e14 <= magnitude < 1e17:
        return "us"
    if 1e11 <= magnitude < 1e14:
        return "ms"
    if 1e8 <= magnitude < 1e11:
        return "s"
    return None


def _date_match_fraction(dt, expected_date):
    valid = dt[dt.notna()]
    if not len(valid):
        return 0.0
    expected = pd.Timestamp(expected_date).date()
    return float((valid.dt.date == expected).mean())


def _validate_parsed_time(series, dt, method, expected_date=None):
    coverage = float(dt.notna().mean())
    if coverage < 0.95:
        sample = [str(v) for v in series.dropna().head(5).tolist()]
        raise ValueError(
            f"Timestamp parse coverage {coverage:.4f} below 95%; "
            f"dtype={series.dtype} method={method} sample={sample}; row-order fallback refused"
        )
    valid = dt[dt.notna()]
    modern = (valid.dt.year >= 2000) & (valid.dt.year <= 2100)
    if float(modern.mean()) < 0.95:
        raise ValueError(
            f"Parsed timestamp range implausible for CICIDS2017 using {method}; "
            "epoch-unit guessing beyond standard magnitude bands refused"
        )
    if expected_date is not None:
        match = _date_match_fraction(dt, expected_date)
        if match < 0.95:
            raise ValueError(
                f"Timestamp campaign-date match {match:.4f} below 95% for expected {expected_date} "
                f"using {method}; ambiguous day/month interpretation refused"
            )
    return dt, method


def parse_time(series, expected_date=None):
    """Parse source timestamps without inventing chronology.

    Supports typed datetimes, standard Unix epoch encodings, and datetime text. For
    original CICIDS2017 campaign files, the day encoded in the filename is used as an
    independent validation constraint. For ambiguous numeric dates, month-first and
    day-first interpretations are tried, but only an interpretation matching the known
    campaign date on >=95% of parsed rows is accepted. There is no row-order,
    synthetic-date, forward-fill or missing-time reconstruction fallback.
    """
    if pd.api.types.is_datetime64_any_dtype(series):
        dt = pd.to_datetime(series, errors="coerce", utc=True)
        return _validate_parsed_time(series, dt, "typed_datetime", expected_date)[0]

    numeric = pd.to_numeric(series, errors="coerce")
    numeric_coverage = float(numeric.notna().mean())
    unit = _epoch_unit(numeric.to_numpy()) if numeric_coverage >= 0.95 else None
    if unit:
        dt = pd.to_datetime(numeric, unit=unit, errors="coerce", utc=True)
        return _validate_parsed_time(series, dt, f"epoch_{unit}", expected_date)[0]

    text = series.astype(str).str.strip()
    candidates = []
    for dayfirst, name in ((False, "monthfirst"), (True, "dayfirst")):
        dt = pd.to_datetime(text, format="mixed", errors="coerce", utc=True, dayfirst=dayfirst)
        coverage = float(dt.notna().mean())
        match = _date_match_fraction(dt, expected_date) if expected_date else None
        candidates.append((dt, f"mixed_datetime_text_{name}", coverage, match))

    if expected_date:
        passing = [row for row in candidates if row[2] >= 0.95 and row[3] is not None and row[3] >= 0.95]
        if not passing:
            details = [{"method": r[1], "coverage": r[2], "date_match": r[3]} for r in candidates]
            raise ValueError(
                f"No timestamp interpretation matches campaign date {expected_date} at >=95%: {details}; "
                "date-format guessing refused"
            )
        # If both interpretations pass, they must agree on the known campaign date; use
        # month-first deterministically. This commonly occurs on dates such as 07/07.
        dt, method, _, _ = passing[0]
        return _validate_parsed_time(series, dt, method, expected_date)[0]

    best = max(candidates, key=lambda r: r[2])
    return _validate_parsed_time(series, best[0], best[1], None)[0]


def _iter_timestamp_labels(path, ts_col, label_col, chunksize=250_000):
    path = Path(path)
    if path.suffix.lower() == ".parquet":
        frame = pd.read_parquet(path, columns=[ts_col, label_col])
        yield frame
        return
    for chunk in pd.read_csv(path, usecols=[ts_col, label_col], chunksize=chunksize, low_memory=False):
        yield chunk


def canonical_family(value):
    return " ".join(str(value).replace("_", " ").strip().casefold().split())


def build_campaign(path):
    path = Path(path)
    ts_col, label_col, column_count = resolve_columns(path)
    expected_date = expected_campaign_date(path)
    if expected_date is None:
        raise ValueError(f"Campaign filename does not identify exactly one CICIDS2017 weekday: {path.name}")
    frames = []
    rows = 0
    parsed = 0
    for chunk in _iter_timestamp_labels(path, ts_col, label_col):
        dt = parse_time(chunk[ts_col], expected_date=expected_date)
        lab = chunk[label_col].astype(str).str.strip()
        good = dt.notna() & lab.notna()
        dt = dt[good]
        lab = lab[good]
        rows += len(chunk)
        parsed += int(good.sum())
        frames.append(pd.DataFrame({"bucket": dt.dt.floor(f"{WINDOW_SECONDS}s"), "label": lab}))
    if not frames:
        raise ValueError(f"No rows in {path.name}")
    data = pd.concat(frames, ignore_index=True)

    def family_tuple(values):
        families = {
            canonical_family(v)
            for v in values
            if canonical_family(v) not in BENIGN and canonical_family(v)
        }
        return tuple(sorted(families))

    grouped = data.groupby("bucket", sort=True)["label"]
    fam = grouped.apply(family_tuple)
    timeline = pd.DataFrame({"time": fam.index, "families": fam.values})
    timeline["attack_now"] = timeline["families"].map(lambda x: int(bool(x)))
    return timeline, {
        "rows": rows,
        "parsed_rows": parsed,
        "timestamp_column": ts_col,
        "label_column": label_col,
        "columns": column_count,
        "expected_campaign_date": expected_date,
        "first_bucket_utc": timeline["time"].iloc[0].isoformat() if len(timeline) else None,
        "last_bucket_utc": timeline["time"].iloc[-1].isoformat() if len(timeline) else None,
    }


def make_sequences(timeline):
    times = timeline["time"].astype("int64").to_numpy() // 10**9
    attack = timeline["attack_now"].to_numpy(np.int8)
    families = timeline["families"].tolist()
    clean, future_attack, histories, steps, cutoffs = [], [], [], [], []
    for i in range(HISTORY - 1, len(timeline) - HORIZON):
        lo = i - HISTORY + 1
        stop = i + HORIZON + 1
        span = times[lo:stop]
        if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == WINDOW_SECONDS):
            continue
        hs = set()
        for row in families[lo:i + 1]:
            hs.update(row)
        histories.append(frozenset(hs))
        steps.append(tuple(frozenset(row) for row in families[i + 1:stop]))
        clean.append(bool(attack[lo:i + 1].max() == 0))
        future_attack.append(int(attack[i + 1:stop].max()))
        cutoffs.append(int(times[i]))
    return {
        "clean": np.asarray(clean, bool),
        "future_attack": np.asarray(future_attack, np.int8),
        "history_families": np.asarray(histories, object),
        "step_families": np.asarray(steps, object),
        "cutoff": np.asarray(cutoffs, np.int64),
    }


def family_presence(sequence, family):
    history = np.asarray([family in row for row in sequence["history_families"]], bool)
    future = np.zeros((len(history), HORIZON), bool)
    for i, row in enumerate(sequence["step_families"]):
        for h, families in enumerate(row):
            future[i, h] = family in families
    return history, future


def _utc(epoch):
    return pd.to_datetime(int(epoch), unit="s", utc=True).isoformat()


def campaign_support(campaigns):
    family_campaigns = {}
    for campaign_id, item in campaigns.items():
        families = sorted({f for row in item["sequence"]["step_families"] for step in row for f in step})
        for family in families:
            family_campaigns.setdefault(family, set()).add(campaign_id)

    rows = []
    for family, ids in sorted(family_campaigns.items()):
        for test_id in sorted(ids):
            seq = campaigns[test_id]["sequence"]
            history, future = family_presence(seq, family)
            any_future = future.any(axis=1)
            positive = any_future
            onset = (~history) & any_future
            clean_onset = seq["clean"] & onset
            negative = seq["clean"] & (seq["future_attack"] == 0)

            dev = 0
            dev_campaigns = []
            for campaign_id, item in campaigns.items():
                if campaign_id == test_id:
                    continue
                s = item["sequence"]
                h, fu = family_presence(s, family)
                free = ~(h | fu.any(axis=1))
                dev += int(free.sum())
                dev_campaigns.append(campaign_id)

            onset_cutoffs = seq["cutoff"][clean_onset]
            rows.append({
                "family": family,
                "test_campaign": test_id,
                "development_campaigns": dev_campaigns,
                "development_family_free_sequences": dev,
                "test_future_positive": int(positive.sum()),
                "test_family_onset_positive": int(onset.sum()),
                "test_clean_history_onset_positive": int(clean_onset.sum()),
                "test_clean_benign_negative": int(negative.sum()),
                "horizon_positive_support": [int(future[:, :h].any(axis=1).sum()) for h in range(1, HORIZON + 1)],
                "first_clean_history_onset_cutoff_utc": _utc(onset_cutoffs[0]) if len(onset_cutoffs) else None,
                "clean_history_onset_cutoffs_utc_sample": [_utc(x) for x in onset_cutoffs[:20]],
            })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-positive", type=int, default=20)
    parser.add_argument("--min-negative", type=int, default=100)
    parser.add_argument("--min-clean-onset", type=int, default=1)
    parser.add_argument("--min-dev", type=int, default=1000)
    args = parser.parse_args()

    out = Path(args.output)
    if out.exists():
        parser.error("Output exists; audit evidence is immutable")
    out.mkdir(parents=True)

    campaigns = {}
    provenance = {}
    for raw in args.input:
        path = Path(raw)
        campaign_id = path.name.removesuffix(".parquet").removesuffix(".csv")
        timeline, meta = build_campaign(path)
        sequence = make_sequences(timeline)
        campaigns[campaign_id] = {"sequence": sequence}
        provenance[campaign_id] = {
            **meta,
            "bytes": int(path.stat().st_size),
            "sha256": sha256(path),
            "timeline_windows": int(len(timeline)),
            "sequence_rows": int(len(sequence["clean"])),
        }

    support = campaign_support(campaigns)
    eligible = [
        row for row in support
        if row["test_future_positive"] >= args.min_positive
        and row["test_clean_benign_negative"] >= args.min_negative
        and row["test_clean_history_onset_positive"] >= args.min_clean_onset
        and row["development_family_free_sequences"] >= args.min_dev
    ]
    eligible.sort(key=lambda r: (-r["test_clean_history_onset_positive"], -r["test_future_positive"], r["family"], r["test_campaign"]))

    report = {
        "protocol": "V53 CICIDS2017 timestamp-preserving whole-campaign unseen-family support audit",
        "window_seconds": WINDOW_SECONDS,
        "history_seconds": HISTORY * WINDOW_SECONDS,
        "horizon_seconds": HORIZON * WINDOW_SECONDS,
        "claim_boundary": "Support audit only; clean-history future onset is a public-dataset pre-onset proxy, not verified successful-compromise lead time or an undisclosed real zero-day.",
        "campaign_provenance": provenance,
        "support": support,
        "eligibility_rule": {
            "min_future_positive": args.min_positive,
            "min_clean_benign_negative": args.min_negative,
            "min_clean_history_onset": args.min_clean_onset,
            "min_development_family_free_sequences": args.min_dev,
        },
        "eligible_family_campaign_pairs": eligible,
        "model_training_permitted": bool(eligible),
        "automatic_containment_approved": False,
    }
    (out / "support.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "eligible_family_campaign_pairs": eligible,
        "model_training_permitted": bool(eligible),
        "campaign_count": len(campaigns),
        "support_pair_count": len(support),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
