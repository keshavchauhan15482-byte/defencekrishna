from __future__ import annotations

"""V35: cross-device clean-onset forecasting on UNSW IoT Attack Traces.

The device split and all evaluation rules are frozen in V35_PROTOCOL_FREEZE.json.
Every model input is an attack-free eight-minute history. Raw device IDs, IPs,
ports and timestamps are never model features; heterogeneous flow headers are
collapsed into a fixed device-agnostic network representation.
"""

import csv
import hashlib
import json
import math
import tempfile
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
OUT = HERE / "artifacts" / "unsw_cross_device_forecast"
OUT.mkdir(parents=True, exist_ok=True)

FLOW_URL = "https://iotanalytics.unsw.edu.au/anomaly-data/flowdata.zip"
ANN_URL = "https://iotanalytics.unsw.edu.au/anomaly-data/annotations.zip"
EXPECTED_FLOW_SHA = "04131cbe9ccd255b2bf001aaee029ae8e84f9542f7440412a1dd28ac80e40295"
EXPECTED_ANN_SHA = "1990c33d5430c4939336d79b08e9ba6a90a8c97621069cb748c3c0282d1eaafd"

TRAIN_DEVICES = ["00166cab6b88", "0017882b9a25", "44650d56ccd3", "50c7bf005639", "70ee50183443", "74c63b29d71d"]
CAL_DEVICES = ["d073d5018308"]
POLICY_DEVICES = ["ec1a5979f489"]
TEST_DEVICES = ["ec1a59832811", "f4f5d88f0a3c"]
ALL_DEVICES = TRAIN_DEVICES + CAL_DEVICES + POLICY_DEVICES + TEST_DEVICES
SEEDS = [42, 43, 44]
HISTORY_MINUTES = 8
FUTURE_SECONDS = 240
POLICY_FPR_BUDGET = 0.05

# Canonical base representation: 21 log-counts + 12 fractions/concentrations.
COUNT_NAMES = [
    "packet_total", "byte_total", "flows",
    "fromlocal_packet", "fromlocal_byte", "tolocal_packet", "tolocal_byte",
    "frominternet_packet", "frominternet_byte", "tointernet_packet", "tointernet_byte",
    "tcp_packet", "tcp_byte", "udp_packet", "udp_byte",
    "icmp_packet", "icmp_byte", "arp_packet", "arp_byte",
    "active_packet_channels", "active_byte_channels",
]
FRACTION_NAMES = [
    "packet_concentration", "byte_concentration",
    "fromlocal_packet_fraction", "tolocal_packet_fraction",
    "frominternet_packet_fraction", "tointernet_packet_fraction",
    "tcp_packet_fraction", "udp_packet_fraction", "icmp_packet_fraction", "arp_packet_fraction",
    "known_protocol_packet_fraction", "internet_packet_fraction",
]
BASE_FEATURE_NAMES = COUNT_NAMES + FRACTION_NAMES


def download(url: str, path: Path) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V35/1.0"})
    h = hashlib.sha256(); size = 0
    with urllib.request.urlopen(req, timeout=180) as r, path.open("wb") as f:
        while True:
            b = r.read(1024 * 1024)
            if not b:
                break
            f.write(b); h.update(b); size += len(b)
    return {"url": url, "bytes": int(size), "sha256": h.hexdigest()}


def normalize_epoch(v: str):
    try:
        x = float(v)
    except Exception:
        return None
    if not math.isfinite(x):
        return None
    if 1e9 <= x <= 4e9:
        return x
    if 1e12 <= x <= 4e12:
        return x / 1000.0
    if 1e15 <= x <= 4e15:
        return x / 1_000_000.0
    return None


def fnum(v: str) -> float:
    try:
        x = float(v)
        return x if math.isfinite(x) else 0.0
    except Exception:
        return 0.0


def device_from_flow_name(name: str):
    base = Path(name).name
    if not base.endswith("_flowstats.csv"):
        return None
    return base.split("_flowstats.csv", 1)[0].lower()


def device_from_annotation_name(name: str):
    base = Path(name).name
    if not base.lower().endswith(".csv"):
        return None
    return Path(base).stem.lower()


def canonical_row(header: list[str], row: list[str]) -> np.ndarray:
    packet_total = byte_total = 0.0
    flows = 0.0
    d = defaultdict(float)
    packet_vals, byte_vals = [], []

    for name, raw in zip(header[1:], row[1:]):
        key = name.strip().lower().replace(" ", "")
        val = max(0.0, fnum(raw))
        if key == "noofflows":
            flows = val
            continue
        is_packet = key.endswith("packet")
        is_byte = key.endswith("byte")
        if not (is_packet or is_byte):
            continue
        suffix = "packet" if is_packet else "byte"
        if is_packet:
            packet_total += val; packet_vals.append(val)
        else:
            byte_total += val; byte_vals.append(val)

        for prefix in ("fromlocal", "tolocal", "frominternet", "tointernet"):
            if key.startswith(prefix):
                d[f"{prefix}_{suffix}"] += val
                break
        if "tcp" in key:
            d[f"tcp_{suffix}"] += val
        elif "udp" in key:
            d[f"udp_{suffix}"] += val
        elif "icmp" in key:
            d[f"icmp_{suffix}"] += val
        elif "arp" in key:
            d[f"arp_{suffix}"] += val

    active_packet = float(sum(v > 0 for v in packet_vals))
    active_byte = float(sum(v > 0 for v in byte_vals))
    pden = max(packet_total, 1.0); bden = max(byte_total, 1.0)
    known_protocol_p = d["tcp_packet"] + d["udp_packet"] + d["icmp_packet"] + d["arp_packet"]
    internet_p = d["frominternet_packet"] + d["tointernet_packet"]

    counts = [
        packet_total, byte_total, flows,
        d["fromlocal_packet"], d["fromlocal_byte"], d["tolocal_packet"], d["tolocal_byte"],
        d["frominternet_packet"], d["frominternet_byte"], d["tointernet_packet"], d["tointernet_byte"],
        d["tcp_packet"], d["tcp_byte"], d["udp_packet"], d["udp_byte"],
        d["icmp_packet"], d["icmp_byte"], d["arp_packet"], d["arp_byte"],
        active_packet, active_byte,
    ]
    fractions = [
        max(packet_vals, default=0.0) / pden,
        max(byte_vals, default=0.0) / bden,
        d["fromlocal_packet"] / pden, d["tolocal_packet"] / pden,
        d["frominternet_packet"] / pden, d["tointernet_packet"] / pden,
        d["tcp_packet"] / pden, d["udp_packet"] / pden,
        d["icmp_packet"] / pden, d["arp_packet"] / pden,
        known_protocol_p / pden, internet_p / pden,
    ]
    return np.asarray([math.log1p(x) for x in counts] + fractions, dtype=np.float32)


def load_flows(z: zipfile.ZipFile):
    devices = {}
    schema = {}
    for info in z.infolist():
        if info.is_dir():
            continue
        device = device_from_flow_name(info.filename)
        if device not in ALL_DEVICES:
            continue
        minute_rows = {}
        minute_ts = {}
        duplicate_minutes = 0
        with z.open(info) as fh:
            reader = csv.reader((raw.decode("utf-8", errors="ignore") for raw in fh))
            try:
                header = next(reader)
            except StopIteration:
                continue
            header = [x.strip() for x in header]
            if not header or header[0].lower() != "timestamp":
                raise RuntimeError(f"{device}: missing Timestamp header")
            for row in reader:
                if len(row) != len(header):
                    continue
                ts = normalize_epoch(row[0])
                if ts is None:
                    continue
                minute = int(ts // 60)
                vec = canonical_row(header, row)
                if minute in minute_rows:
                    duplicate_minutes += 1
                    minute_rows[minute] = (minute_rows[minute] + vec) / 2.0
                    minute_ts[minute] = min(minute_ts[minute], ts)
                else:
                    minute_rows[minute] = vec
                    minute_ts[minute] = ts
        devices[device] = {"rows": minute_rows, "timestamps": minute_ts}
        schema[device] = {
            "archive_member": info.filename,
            "field_count": len(header),
            "minute_rows": len(minute_rows),
            "duplicate_minutes": duplicate_minutes,
        }
    missing = sorted(set(ALL_DEVICES) - set(devices))
    if missing:
        raise RuntimeError(f"missing flow devices: {missing}")
    return devices, schema


def load_events(z: zipfile.ZipFile):
    events = defaultdict(list)
    for info in z.infolist():
        if info.is_dir():
            continue
        device = device_from_annotation_name(info.filename)
        if device not in ALL_DEVICES:
            continue
        text = z.read(info).decode("utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split(",")]
            if len(parts) < 3:
                continue
            start = normalize_epoch(parts[0]); end = normalize_epoch(parts[1])
            if start is None or end is None or end < start:
                continue
            label = parts[-1]
            event_id = f"{device}:{line_no}:{int(start*1000)}"
            events[device].append({
                "id": event_id, "device": device, "start": float(start), "end": float(end), "label": label,
            })
    for device in ALL_DEVICES:
        events[device].sort(key=lambda e: (e["start"], e["end"], e["id"]))
        if not events[device]:
            raise RuntimeError(f"{device}: no parseable annotation events")
    return events


def minute_overlaps_event(minute: int, events: list[dict]) -> bool:
    lo, hi = minute * 60.0, (minute + 1) * 60.0
    return any(e["start"] < hi and e["end"] > lo for e in events)


def history_summary(H: np.ndarray) -> np.ndarray:
    q25 = np.quantile(H, 0.25, axis=0)
    q75 = np.quantile(H, 0.75, axis=0)
    med = np.median(H, axis=0)
    scale = np.maximum(q75 - q25, 0.10)
    Z = (H - med) / scale
    recent2 = Z[-2:].mean(axis=0) - Z[-4:-2].mean(axis=0)
    recent4 = Z[-4:].mean(axis=0) - Z[:4].mean(axis=0)
    return np.concatenate([
        Z[-1], Z.mean(axis=0), Z.std(axis=0), Z.max(axis=0),
        Z[-1] - Z[0], recent2, recent4,
    ]).astype(np.float32)


def build_device_samples(device: str, flow: dict, events: list[dict]):
    rows = flow["rows"]; timestamps = flow["timestamps"]
    minutes = sorted(rows)
    minute_set = set(minutes)
    attack_minute = {m: minute_overlaps_event(m, events) for m in minutes}
    samples = []
    for m in minutes:
        history_minutes = list(range(m - HISTORY_MINUTES + 1, m + 1))
        future_minutes = list(range(m + 1, m + 5))
        if not all(x in minute_set for x in history_minutes + future_minutes):
            continue
        if any(attack_minute[x] for x in history_minutes):
            continue
        cutoff_ts = float(timestamps[m])
        future_events = [e for e in events if cutoff_ts < e["start"] <= cutoff_ts + FUTURE_SECONDS]
        if future_events:
            y = 1
            event_ids = [e["id"] for e in future_events]
        else:
            if any(attack_minute[x] for x in future_minutes):
                continue
            y = 0
            event_ids = []
        H = np.stack([rows[x] for x in history_minutes])
        samples.append({
            "x": history_summary(H), "y": y, "device": device,
            "cutoff_ts": cutoff_ts, "event_ids": event_ids,
        })
    return samples


def split_name(device: str):
    if device in TRAIN_DEVICES: return "train"
    if device in CAL_DEVICES: return "calibration"
    if device in POLICY_DEVICES: return "policy"
    if device in TEST_DEVICES: return "test"
    raise KeyError(device)


def calibrator(raw_p, y):
    y = np.asarray(y, int)
    if len(np.unique(y)) < 2:
        raise RuntimeError("calibration device lacks both classes")
    p = np.clip(np.asarray(raw_p, float), 1e-6, 1 - 1e-6)
    x = np.log(p / (1 - p)).reshape(-1, 1)
    return LogisticRegression(C=1e3, max_iter=500).fit(x, y)


def apply_cal(model, p):
    q = np.clip(np.asarray(p, float), 1e-6, 1 - 1e-6)
    return model.predict_proba(np.log(q / (1 - q)).reshape(-1, 1))[:, 1]


def policy_threshold(scores, y):
    benign = np.asarray(scores, float)[np.asarray(y, int) == 0]
    if len(benign) < 100:
        raise RuntimeError(f"policy benign support too small: {len(benign)}")
    return float(np.quantile(benign, 1.0 - POLICY_FPR_BUDGET, method="higher"))


def binary_metrics(y, p, threshold):
    y = np.asarray(y, int); p = np.asarray(p, float); pred = p >= threshold
    neg = y == 0; pos = y == 1
    tp = int(np.sum(pred & pos)); fp = int(np.sum(pred & neg)); fn = int(np.sum((~pred) & pos))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, int(pos.sum()))
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    return {
        "n": int(len(y)), "benign_n": int(neg.sum()), "positive_n": int(pos.sum()),
        "fpr": float(fp / max(1, int(neg.sum()))), "recall": float(recall),
        "precision": float(precision), "f1": float(f1),
        "pr_auc": float(average_precision_score(y, p)) if pos.any() else None,
        "false_positives": fp, "true_positives": tp,
    }


def event_metrics(samples, scores, threshold, events_by_device):
    event_lookup = {e["id"]: e for d in TEST_DEVICES for e in events_by_device[d]}
    candidates = defaultdict(list)
    for i, s in enumerate(samples):
        for eid in s["event_ids"]:
            if eid in event_lookup:
                candidates[eid].append(i)
    rows = []
    detected_leads = []
    for device in TEST_DEVICES:
        for e in events_by_device[device]:
            idx = candidates.get(e["id"], [])
            if not idx:
                rows.append({
                    "event_id": e["id"], "device": device, "label": e["label"],
                    "start": e["start"], "candidate_windows": 0, "evaluable": False,
                    "detected": False, "max_lead_seconds": None,
                })
                continue
            hit = [i for i in idx if scores[i] >= threshold]
            leads = [e["start"] - samples[i]["cutoff_ts"] for i in hit]
            max_lead = max(leads) if leads else None
            if max_lead is not None:
                detected_leads.append(max_lead)
            rows.append({
                "event_id": e["id"], "device": device, "label": e["label"],
                "start": e["start"], "candidate_windows": len(idx), "evaluable": True,
                "detected": bool(hit), "max_lead_seconds": float(max_lead) if max_lead is not None else None,
            })
    evaluable = [x for x in rows if x["evaluable"]]
    detected = [x for x in evaluable if x["detected"]]
    return {
        "total_annotated_test_events": len(rows),
        "evaluable_event_n": len(evaluable),
        "unsupported_event_n": len(rows) - len(evaluable),
        "event_recall": float(len(detected) / max(1, len(evaluable))),
        "detected_event_n": len(detected),
        "detected_event_median_max_lead_seconds": float(np.median(detected_leads)) if detected_leads else 0.0,
        "detected_event_mean_max_lead_seconds": float(np.mean(detected_leads)) if detected_leads else 0.0,
        "events": rows,
    }


def fit_and_score(X, y, split, samples, events_by_device, seed):
    tr = np.where(split == "train")[0]
    ca = np.where(split == "calibration")[0]
    po = np.where(split == "policy")[0]
    te = np.where(split == "test")[0]
    for name, idx, min_pos in (("train", tr, 20), ("calibration", ca, 5), ("policy", po, 5), ("test", te, 10)):
        counts = np.bincount(y[idx], minlength=2)
        if len(idx) < 50 or counts[0] < 30 or counts[1] < min_pos:
            raise RuntimeError(f"{name} support insufficient: n={len(idx)} counts={counts.tolist()}")

    scaler = StandardScaler().fit(X[tr])
    Z = scaler.transform(X)

    primary = HistGradientBoostingClassifier(
        max_iter=350, learning_rate=0.04, max_leaf_nodes=31,
        min_samples_leaf=12, l2_regularization=2.0,
        class_weight="balanced", random_state=seed,
    ).fit(Z[tr], y[tr])
    p_ca_raw = primary.predict_proba(Z[ca])[:, 1]
    cal_primary = calibrator(p_ca_raw, y[ca])
    p_po = apply_cal(cal_primary, primary.predict_proba(Z[po])[:, 1])
    th_primary = policy_threshold(p_po, y[po])
    p_te = apply_cal(cal_primary, primary.predict_proba(Z[te])[:, 1])

    baseline = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1500).fit(Z[tr], y[tr])
    cal_base = calibrator(baseline.predict_proba(Z[ca])[:, 1], y[ca])
    b_po = apply_cal(cal_base, baseline.predict_proba(Z[po])[:, 1])
    th_base = policy_threshold(b_po, y[po])
    b_te = apply_cal(cal_base, baseline.predict_proba(Z[te])[:, 1])

    test_samples = [samples[i] for i in te]
    primary_binary = binary_metrics(y[te], p_te, th_primary)
    primary_events = event_metrics(test_samples, p_te, th_primary, events_by_device)
    baseline_binary = binary_metrics(y[te], b_te, th_base)
    baseline_events = event_metrics(test_samples, b_te, th_base, events_by_device)

    return {
        "seed": seed,
        "primary": {
            "model": "HistGradientBoostingClassifier",
            "policy_threshold": th_primary,
            "policy": binary_metrics(y[po], p_po, th_primary),
            "test": primary_binary,
            "event_test": primary_events,
        },
        "logistic_baseline": {
            "policy_threshold": th_base,
            "policy": binary_metrics(y[po], b_po, th_base),
            "test": baseline_binary,
            "event_test": baseline_events,
        },
    }


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v35-") as tmp:
        td = Path(tmp); fp = td / "flowdata.zip"; ap = td / "annotations.zip"
        flow_meta = download(FLOW_URL, fp); ann_meta = download(ANN_URL, ap)
        if flow_meta["sha256"] != EXPECTED_FLOW_SHA:
            raise RuntimeError(f"flow archive hash mismatch: {flow_meta['sha256']}")
        if ann_meta["sha256"] != EXPECTED_ANN_SHA:
            raise RuntimeError(f"annotation archive hash mismatch: {ann_meta['sha256']}")
        with zipfile.ZipFile(fp) as zf:
            flows, flow_schema = load_flows(zf)
        with zipfile.ZipFile(ap) as za:
            events = load_events(za)

    samples = []
    per_device = {}
    for device in ALL_DEVICES:
        ds = build_device_samples(device, flows[device], events[device])
        samples.extend(ds)
        per_device[device] = {
            "split": split_name(device), "samples": len(ds),
            "positive_samples": int(sum(x["y"] for x in ds)),
            "benign_samples": int(sum(1 - x["y"] for x in ds)),
            "annotated_events": len(events[device]),
        }
        print(f"V35 {device} split={split_name(device)} samples={len(ds)} positives={per_device[device]['positive_samples']} events={len(events[device])}", flush=True)

    if not samples:
        raise RuntimeError("no V35 samples")
    X = np.stack([s["x"] for s in samples])
    y = np.asarray([s["y"] for s in samples], int)
    split = np.asarray([split_name(s["device"]) for s in samples], object)

    runs = []
    for seed in SEEDS:
        print(f"V35 seed={seed}", flush=True)
        r = fit_and_score(X, y, split, samples, events, seed)
        runs.append(r)
        print(json.dumps({
            "seed": seed,
            "primary_test": r["primary"]["test"],
            "primary_event_test": {k: v for k, v in r["primary"]["event_test"].items() if k != "events"},
            "baseline_test": r["logistic_baseline"]["test"],
        }, indent=2), flush=True)

    primary_test = [r["primary"]["test"] for r in runs]
    primary_events = [r["primary"]["event_test"] for r in runs]
    baseline_test = [r["logistic_baseline"]["test"] for r in runs]
    baseline_events = [r["logistic_baseline"]["event_test"] for r in runs]

    primary_mean = {
        "fpr": float(np.mean([x["fpr"] for x in primary_test])),
        "sequence_recall": float(np.mean([x["recall"] for x in primary_test])),
        "precision": float(np.mean([x["precision"] for x in primary_test])),
        "f1": float(np.mean([x["f1"] for x in primary_test])),
        "pr_auc": float(np.mean([x["pr_auc"] for x in primary_test])),
        "event_recall": float(np.mean([x["event_recall"] for x in primary_events])),
        "evaluable_event_n": int(min(x["evaluable_event_n"] for x in primary_events)),
        "unsupported_event_n": int(max(x["unsupported_event_n"] for x in primary_events)),
        "detected_event_median_max_lead_seconds": float(np.mean([x["detected_event_median_max_lead_seconds"] for x in primary_events])),
    }
    baseline_mean = {
        "fpr": float(np.mean([x["fpr"] for x in baseline_test])),
        "sequence_recall": float(np.mean([x["recall"] for x in baseline_test])),
        "precision": float(np.mean([x["precision"] for x in baseline_test])),
        "f1": float(np.mean([x["f1"] for x in baseline_test])),
        "pr_auc": float(np.mean([x["pr_auc"] for x in baseline_test])),
        "event_recall": float(np.mean([x["event_recall"] for x in baseline_events])),
        "evaluable_event_n": int(min(x["evaluable_event_n"] for x in baseline_events)),
        "detected_event_median_max_lead_seconds": float(np.mean([x["detected_event_median_max_lead_seconds"] for x in baseline_events])),
    }
    gate = {
        "test_fpr_pass": primary_mean["fpr"] <= 0.05,
        "test_event_recall_pass": primary_mean["event_recall"] >= 0.80,
        "test_sequence_recall_pass": primary_mean["sequence_recall"] >= 0.70,
        "test_event_support_pass": primary_mean["evaluable_event_n"] >= 20,
        "lead_time_pass": primary_mean["detected_event_median_max_lead_seconds"] >= 60,
    }
    gate["pass"] = bool(all(gate.values()))

    report = {
        "schema": "krishna-v35-unsw-cross-device-clean-onset-dev-v1",
        "source_provenance": {"flow": flow_meta, "annotations": ann_meta},
        "device_split": {"train": TRAIN_DEVICES, "calibration": CAL_DEVICES, "policy": POLICY_DEVICES, "test": TEST_DEVICES},
        "strict_network_only": True,
        "raw_identity_model_features": False,
        "base_feature_names": BASE_FEATURE_NAMES,
        "history_summary_feature_count": int(X.shape[1]),
        "per_device_support": per_device,
        "runs": runs,
        "primary_mean": primary_mean,
        "logistic_baseline_mean": baseline_mean,
        "development_gate": gate,
        "claim_scope": "cross-device clean-onset forecasting only; attack families are not held out by label",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "REPORT.md").write_text(
        "# V35 UNSW cross-device clean-onset forecasting\n\n"
        "Two test devices are completely absent from train/calibration/policy. All model histories are attack-free.\n\n"
        "```json\n" + json.dumps({
            "primary_mean": primary_mean,
            "logistic_baseline_mean": baseline_mean,
            "development_gate": gate,
            "per_device_support": per_device,
        }, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps({"primary_mean": primary_mean, "logistic_baseline_mean": baseline_mean, "development_gate": gate}, indent=2), flush=True)
    if not gate["pass"]:
        raise RuntimeError("V35 cross-device clean-onset development gate not met")


if __name__ == "__main__":
    main()
