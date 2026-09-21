"""V89 one-shot external IoT-23 transfer benchmark.

A generic host-minute flow detector is trained and selected ONLY on UNSW-NB15 raw
traffic. The IoT-23 files are opened only after model type, preprocessing, and alert
threshold have been frozen to disk. This benchmark measures cross-dataset transfer to
an independently frozen Mirai capture and a separately frozen benign Echo-Dot capture.

This is an external captured/lab IoT traffic benchmark, not production-enterprise
validation, not a stage benchmark, and not verified pre-compromise forecasting.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v59_unsw_independent_replication import norm, read_feature_names

FEATURES = [
    "log_flow_count", "log_unique_dst", "log_unique_dport",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "log_total_bytes", "log_total_pkts",
    "mean_log_duration", "p95_log_duration",
    "resp_bytes_ratio", "resp_pkts_ratio",
    "small_flow_ratio", "no_response_ratio", "fanout_ratio",
    "mean_log_bytes_per_flow", "mean_log_pkts_per_flow",
]
FPR_BUDGET = 0.01
WINDOW_SECONDS = 60


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def _pick(mapping, *names):
    for name in names:
        key = norm(name)
        if key in mapping:
            return mapping[key]
    return None


def _numeric(s):
    return pd.to_numeric(s, errors="coerce").fillna(0.0).clip(lower=0.0)


def aggregate_flows(flow: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Create source-host/minute features with no dataset-specific attack signatures."""
    required = {"ts", "src", "dst", "dport", "proto", "duration", "orig_bytes",
                "resp_bytes", "orig_pkts", "resp_pkts", "y"}
    missing = required - set(flow.columns)
    if missing:
        raise ValueError(f"canonical flow columns missing: {sorted(missing)}")
    f = flow.copy()
    f = f[np.isfinite(pd.to_numeric(f["ts"], errors="coerce"))].copy()
    if not len(f):
        raise RuntimeError("no timestamped flows")
    for c in ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
        f[c] = _numeric(f[c])
    f["dport"] = pd.to_numeric(f["dport"], errors="coerce").fillna(0).clip(0, 65535).astype(int)
    f["proto"] = f["proto"].astype(str).str.lower()
    f["bucket"] = (pd.to_numeric(f["ts"], errors="coerce") // WINDOW_SECONDS).astype("int64")
    f["total_bytes_f"] = f["orig_bytes"] + f["resp_bytes"]
    f["total_pkts_f"] = f["orig_pkts"] + f["resp_pkts"]
    f["log_duration_f"] = np.log1p(f["duration"])
    f["small_f"] = (f["total_bytes_f"] < 200).astype(float)
    f["no_response_f"] = ((f["resp_bytes"] <= 0) & (f["resp_pkts"] <= 0)).astype(float)
    f["tcp_f"] = (f["proto"] == "tcp").astype(float)
    f["udp_f"] = (f["proto"] == "udp").astype(float)
    f["icmp_f"] = f["proto"].str.startswith("icmp").astype(float)
    f["log_bytes_f"] = np.log1p(f["total_bytes_f"])
    f["log_pkts_f"] = np.log1p(f["total_pkts_f"])

    keys = ["src", "bucket"]
    g = f.groupby(keys, sort=True, observed=True)
    base = g.agg(
        flow_count=("dst", "size"),
        unique_dst=("dst", "nunique"),
        unique_dport=("dport", "nunique"),
        tcp_ratio=("tcp_f", "mean"), udp_ratio=("udp_f", "mean"), icmp_ratio=("icmp_f", "mean"),
        total_bytes=("total_bytes_f", "sum"), total_pkts=("total_pkts_f", "sum"),
        mean_log_duration=("log_duration_f", "mean"),
        resp_bytes=("resp_bytes", "sum"), orig_bytes=("orig_bytes", "sum"),
        resp_pkts=("resp_pkts", "sum"), orig_pkts=("orig_pkts", "sum"),
        small_flow_ratio=("small_f", "mean"), no_response_ratio=("no_response_f", "mean"),
        mean_log_bytes_per_flow=("log_bytes_f", "mean"),
        mean_log_pkts_per_flow=("log_pkts_f", "mean"),
        y=("y", "max"),
    ).reset_index()
    p95 = g["log_duration_f"].quantile(0.95).rename("p95_log_duration").reset_index()
    base = base.merge(p95, on=keys, how="left", validate="one_to_one")
    denom_b = (base["orig_bytes"] + base["resp_bytes"]).replace(0, np.nan)
    denom_p = (base["orig_pkts"] + base["resp_pkts"]).replace(0, np.nan)
    base["log_flow_count"] = np.log1p(base["flow_count"])
    base["log_unique_dst"] = np.log1p(base["unique_dst"])
    base["log_unique_dport"] = np.log1p(base["unique_dport"])
    base["log_total_bytes"] = np.log1p(base["total_bytes"])
    base["log_total_pkts"] = np.log1p(base["total_pkts"])
    base["resp_bytes_ratio"] = (base["resp_bytes"] / denom_b).fillna(0.0)
    base["resp_pkts_ratio"] = (base["resp_pkts"] / denom_p).fillna(0.0)
    base["fanout_ratio"] = (base["unique_dst"] / base["flow_count"].clip(lower=1)).fillna(0.0)
    X = base[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    audit = {
        "flows": int(len(f)), "windows": int(len(base)),
        "positive_windows": int((base["y"] > 0).sum()),
        "negative_windows": int((base["y"] <= 0).sum()),
        "source_hosts": int(base["src"].nunique()),
    }
    return pd.concat([base[["src", "bucket", "y"]], X], axis=1), audit


def load_unsw_shard(path: Path, names: list[str]) -> pd.DataFrame:
    m = {norm(c): c for c in names}
    wanted_keys = {"srcip", "dstip", "sport", "dsport", "proto", "dur", "sbytes", "dbytes",
                   "spkts", "dpkts", "stime", "attackcat", "label"}
    wanted = [c for c in names if norm(c) in wanted_keys]
    df = pd.read_csv(path, header=None, names=names, usecols=wanted, low_memory=False)
    mm = {norm(c): c for c in df.columns}
    def col(*x): return _pick(mm, *x)
    required = [col("srcip"), col("dstip"), col("dsport"), col("proto"), col("dur"),
                col("sbytes"), col("dbytes"), col("spkts"), col("dpkts"), col("stime"), col("label")]
    if any(x is None for x in required):
        raise RuntimeError(f"UNSW columns unresolved: {mm}")
    return pd.DataFrame({
        "ts": pd.to_numeric(df[col("stime")], errors="coerce"),
        "src": df[col("srcip")].astype(str), "dst": df[col("dstip")].astype(str),
        "dport": df[col("dsport")], "proto": df[col("proto")],
        "duration": df[col("dur")], "orig_bytes": df[col("sbytes")], "resp_bytes": df[col("dbytes")],
        "orig_pkts": df[col("spkts")], "resp_pkts": df[col("dpkts")],
        "y": pd.to_numeric(df[col("label")], errors="coerce").fillna(0).astype(int).clip(0, 1),
    })


def load_unsw(root: Path):
    shards = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if len(shards) != 4:
        raise RuntimeError(f"Expected four UNSW raw shards, got {shards}")
    probe = pd.read_csv(shards[0], header=None, nrows=1)
    feature_files = sorted(root.rglob("*features*.csv")) + sorted(root.rglob("*Features*.csv"))
    if not feature_files:
        raise RuntimeError("UNSW feature definition missing")
    names = read_feature_names(feature_files[0], int(probe.shape[1]))
    train_parts, audits = [], []
    for i, shard in enumerate(shards):
        windows, audit = aggregate_flows(load_unsw_shard(shard, names))
        audit.update(shard=shard.name, sha256=sha256(shard))
        audits.append(audit)
        if i < 3:
            train_parts.append(windows)
        else:
            validation = windows
    return pd.concat(train_parts, ignore_index=True), validation.reset_index(drop=True), audits


def model_candidates():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(C=0.5, class_weight="balanced", max_iter=2500, random_state=8901)),
        ]),
        "histgb": HistGradientBoostingClassifier(
            learning_rate=0.05, max_iter=220, max_leaf_nodes=15, min_samples_leaf=20,
            l2_regularization=4.0, class_weight="balanced", random_state=8901,
        ),
        "extratrees": ExtraTreesClassifier(
            n_estimators=300, max_features="sqrt", min_samples_leaf=3,
            class_weight="balanced_subsample", n_jobs=1, random_state=8901,
        ),
    }


def threshold_at_fpr(y, score, budget=FPR_BUDGET):
    y = np.asarray(y, dtype=int); score = np.asarray(score, dtype=float)
    neg = np.sort(score[y == 0])
    if len(neg) < 100:
        raise RuntimeError("Need >=100 benign validation windows")
    # Candidate thresholds include just above each observed score. Select the lowest
    # threshold whose empirical benign FPR is <= budget, maximizing recall without test use.
    k = int(math.floor(budget * len(neg)))
    if k <= 0:
        threshold = float(np.nextafter(neg[-1], np.inf))
    else:
        threshold = float(np.nextafter(neg[-k], np.inf))
    return threshold


def metric(y, score, threshold):
    y = np.asarray(y, dtype=int); score = np.asarray(score, dtype=float)
    pred = score >= threshold; pos = y == 1; neg = ~pos
    tp = int(np.sum(pred & pos)); fn = int(np.sum((~pred) & pos))
    fp = int(np.sum(pred & neg)); tn = int(np.sum((~pred) & neg))
    recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1); f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {"support": int(len(y)), "positives": int(pos.sum()), "negatives": int(neg.sum()),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn, "threshold": float(threshold),
            "recall": float(recall), "fpr": float(fpr), "precision": float(precision), "f1": float(f1),
            "pr_auc": float(average_precision_score(y, score)) if len(np.unique(y)) > 1 else None,
            "roc_auc": float(roc_auc_score(y, score)) if len(np.unique(y)) > 1 else None}


def select_on_unsw(train, validation):
    Xtr = train[FEATURES].to_numpy(dtype=float); ytr = train["y"].to_numpy(dtype=int)
    Xv = validation[FEATURES].to_numpy(dtype=float); yv = validation["y"].to_numpy(dtype=int)
    rows = []
    fitted = {}
    for name, model in model_candidates().items():
        model.fit(Xtr, ytr)
        p = np.asarray(model.predict_proba(Xv)[:, 1], dtype=float)
        t = threshold_at_fpr(yv, p)
        m = metric(yv, p, t)
        rows.append({"model": name, **m})
        fitted[name] = model
    feasible = [r for r in rows if r["fpr"] <= FPR_BUDGET + 1e-12]
    if not feasible:
        feasible = rows
    feasible.sort(key=lambda r: (r["recall"], r["precision"], r["pr_auc"] or 0.0, -r["fpr"]), reverse=True)
    winner = feasible[0]
    return fitted[winner["model"]], float(winner["threshold"]), winner, rows


def read_zeek_labeled(path: Path, host_ip: str):
    fields = None
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                break
    if not fields:
        raise RuntimeError(f"Zeek #fields header missing in {path}")
    raw = pd.read_csv(path, sep="\t", comment="#", names=fields, dtype=str, low_memory=False)
    required = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "duration",
                "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "label"]
    missing = [c for c in required if c not in raw.columns]
    if missing:
        raise RuntimeError(f"IoT-23 Zeek fields missing: {missing}; got={fields}")
    raw = raw[raw["id.orig_h"].astype(str) == str(host_ip)].copy()
    if not len(raw):
        raise RuntimeError(f"No device-origin flows for {host_ip}")
    label = raw["label"].astype(str).str.lower().str.strip()
    y = label.str.contains("malicious").astype(int)
    detailed_col = "detailed-label" if "detailed-label" in raw.columns else None
    detailed = raw[detailed_col].astype(str).str.strip() if detailed_col else pd.Series("unknown", index=raw.index)
    flow = pd.DataFrame({
        "ts": pd.to_numeric(raw["ts"], errors="coerce"),
        "src": raw["id.orig_h"].astype(str), "dst": raw["id.resp_h"].astype(str),
        "dport": raw["id.resp_p"], "proto": raw["proto"], "duration": raw["duration"],
        "orig_bytes": raw["orig_bytes"], "resp_bytes": raw["resp_bytes"],
        "orig_pkts": raw["orig_pkts"], "resp_pkts": raw["resp_pkts"], "y": y,
        "detail": detailed,
    })
    return flow


def external_windows(flow: pd.DataFrame):
    windows, audit = aggregate_flows(flow.drop(columns=["detail"]))
    f = flow.copy()
    f["bucket"] = (pd.to_numeric(f["ts"], errors="coerce") // WINDOW_SECONDS).astype("Int64")
    labels = {}
    for bucket, group in f[f["y"] > 0].groupby("bucket"):
        labels[int(bucket)] = sorted({x for x in group["detail"].astype(str) if x and x not in {"-", "nan"}})
    return windows, audit, labels


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--unsw-root", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--malicious", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output)
    if out.exists():
        ap.error("Output exists; V89 evidence is immutable")
    out.mkdir(parents=True)

    freeze_path = Path(args.freeze)
    frozen = json.loads(freeze_path.read_text())
    if frozen.get("selection_uses_test_metrics") is not False or frozen.get("fit_on_iot23") is not False:
        raise RuntimeError("External freeze contract is not independent")

    # Phase A: all fitting/model selection/threshold selection happens before opening IoT-23.
    train, validation, unsw_audit = load_unsw(Path(args.unsw_root))
    model, threshold, winner, candidate_rows = select_on_unsw(train, validation)
    pretest = {
        "protocol": "V89 pre-test model freeze",
        "training_dataset": "UNSW-NB15 raw four-shard corpus",
        "training_shards": unsw_audit,
        "feature_schema": FEATURES,
        "window_seconds": WINDOW_SECONDS,
        "grouping": "source-host minute windows",
        "candidate_selection_dataset": "UNSW shard 4 only",
        "test_dataset_used_for_selection": False,
        "fpr_budget": FPR_BUDGET,
        "winner": winner,
        "all_candidates": candidate_rows,
    }
    pretest_path = out / "pretest_model_selection.json"
    pretest_path.write_text(json.dumps(pretest, indent=2, allow_nan=False) + "\n")
    pretest_sha = sha256(pretest_path)
    print("PRETEST MODEL FROZEN", json.dumps({"sha256": pretest_sha, "winner": winner}, indent=2), flush=True)

    # Phase B: only now read the independently precommitted IoT-23 captures.
    mal_path = Path(args.malicious); ben_path = Path(args.benign)
    mal_flow = read_zeek_labeled(mal_path, frozen["malicious_capture"]["host_ip"])
    ben_flow = read_zeek_labeled(ben_path, frozen["benign_capture"]["host_ip"])
    mal_win, mal_audit, label_windows = external_windows(mal_flow)
    ben_win, ben_audit, _ = external_windows(ben_flow)

    mal_positive = mal_win[mal_win["y"] > 0].copy()
    ben_negative = ben_win.copy()
    if len(mal_positive) < 20 or len(ben_negative) < 20:
        raise RuntimeError(f"Insufficient external support mal={len(mal_positive)} benign={len(ben_negative)}")
    mal_score = model.predict_proba(mal_positive[FEATURES].to_numpy(dtype=float))[:, 1]
    ben_score = model.predict_proba(ben_negative[FEATURES].to_numpy(dtype=float))[:, 1]
    recall_metric = metric(np.ones(len(mal_score), dtype=int), mal_score, threshold)
    fpr_metric = metric(np.zeros(len(ben_score), dtype=int), ben_score, threshold)
    y_pool = np.concatenate([np.ones(len(mal_score), dtype=int), np.zeros(len(ben_score), dtype=int)])
    s_pool = np.concatenate([mal_score, ben_score])
    pooled = metric(y_pool, s_pool, threshold)

    mal_pred = mal_score >= threshold
    pred_by_bucket = {int(b): bool(p) for b, p in zip(mal_positive["bucket"], mal_pred)}
    per_label = {}
    for bucket, labels in label_windows.items():
        if bucket not in pred_by_bucket:
            continue
        for label in labels:
            row = per_label.setdefault(label, {"support_windows": 0, "detected_windows": 0})
            row["support_windows"] += 1
            row["detected_windows"] += int(pred_by_bucket[bucket])
    for row in per_label.values():
        row["recall"] = row["detected_windows"] / max(row["support_windows"], 1)

    report = {
        "protocol": "V89 independent external IoT-23 one-shot transfer evaluation",
        "claim_boundary": (
            "Cross-dataset transfer from UNSW-NB15 development traffic to independently frozen IoT-23 v2 "
            "captured IoT traffic. IoT-23 labels/metrics were not used for fitting, feature selection, model "
            "selection or threshold selection. This is controlled/lab IoT traffic, not production-enterprise "
            "traffic; it does not establish MITRE-stage accuracy or verified pre-compromise warning."
        ),
        "freeze_sha256": sha256(freeze_path),
        "pretest_model_selection_sha256": pretest_sha,
        "selection_uses_iot23_metrics": False,
        "fit_on_iot23": False,
        "threshold_origin": "UNSW-NB15 shard-4 benign validation windows at <=1% empirical FPR",
        "selected_model": winner,
        "external_sources": {
            "malicious": {"scenario": frozen["malicious_capture"]["scenario"], "host_ip": frozen["malicious_capture"]["host_ip"],
                          "sha256": sha256(mal_path), **mal_audit},
            "benign": {"scenario": frozen["benign_capture"]["scenario"], "host_ip": frozen["benign_capture"]["host_ip"],
                       "sha256": sha256(ben_path), **ben_audit},
        },
        "external_metrics": {
            "attack_recall_on_explicit_malicious_host_minutes": recall_metric["recall"],
            "benign_false_positive_rate_on_echo_host_minutes": fpr_metric["fpr"],
            "benign_false_alert_windows": fpr_metric["fp"],
            "benign_window_count": fpr_metric["negatives"],
            "malicious_window_count": recall_metric["positives"],
            "pooled_precision": pooled["precision"],
            "pooled_f1": pooled["f1"],
            "pooled_pr_auc": pooled["pr_auc"],
            "pooled_roc_auc": pooled["roc_auc"],
        },
        "per_malicious_detailed_label": per_label,
        "metric_units": "source-device 60-second windows; only device-origin Zeek flows",
        "no_test_tuning_contract": {
            "iot23_opened_after_pretest_manifest_written": True,
            "test_metrics_used_for_feature_selection": False,
            "test_metrics_used_for_model_selection": False,
            "test_metrics_used_for_threshold_selection": False,
            "capture_switched_after_results": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("V89 EXTERNAL RESULT", json.dumps(report["external_metrics"], indent=2), flush=True)
    print("V89 PER LABEL", json.dumps(per_label, indent=2), flush=True)


if __name__ == "__main__":
    main()
