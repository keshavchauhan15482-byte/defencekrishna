"""V92 domain-hardened, sealed ToN-IoT external one-shot evaluation.

The external ToN-IoT file is not opened by the prepare command. Model architecture,
portable feature view, and one fixed operating threshold are selected only from sources
that are already exposed development evidence: UNSW-NB15, the preserved IoT-23 first
external source, and the preserved RT-IoT2022 first external source. The prepare command
serializes the selected model and immutable pretest manifest. Only a later score command
may open ToN-IoT.

This is binary attack-transfer evidence on public cyber-range traffic. It is not a
zero-day semantic claim, attacker-stage validation, verified pre-compromise lead-time
proof, customer production validation, or authorization for autonomous containment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v59_unsw_independent_replication import norm, read_feature_names
from .v89_iot23_external_one_shot import load_unsw_shard
from .v89_iot23_external_one_shot_fixed import read_zeek_labeled_whitespace

FPR_GATE = 0.01
# Deliberately more conservative calibration budget to absorb source drift while the
# externally reported gate remains <=1%. This constant is fixed before ToN-IoT access.
CAL_FPR_TARGET = 0.0025
RECALL_GATE = 0.80
SEED = 9201
MAX_FIT_PER_SOURCE_CLASS = 100_000
MAX_CAL_PER_SOURCE_CLASS = 60_000
MAX_EVAL_PER_SOURCE_CLASS = 80_000

PORTABLE8 = [
    "log_total_bytes", "log_total_packets", "response_byte_ratio",
    "response_packet_ratio", "tcp_flag", "udp_flag", "icmp_flag",
    "log_bytes_per_packet",
]
PORTABLE11 = [
    "log_total_bytes", "log_total_packets", "log_duration",
    "response_byte_ratio", "response_packet_ratio", "tcp_flag", "udp_flag",
    "icmp_flag", "log_bytes_per_packet", "log_packets_per_second",
    "log_bytes_per_second",
]
FEATURE_VIEWS = {"portable8": PORTABLE8, "portable11": PORTABLE11}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def pick(mapping, *names):
    for name in names:
        k = norm(name)
        if k in mapping:
            return mapping[k]
    return None


def numeric(s):
    return pd.to_numeric(s, errors="coerce").fillna(0.0).clip(lower=0.0)


def portable_frame(flow: pd.DataFrame) -> pd.DataFrame:
    b0 = numeric(flow["orig_bytes"]); b1 = numeric(flow["resp_bytes"])
    p0 = numeric(flow["orig_pkts"]); p1 = numeric(flow["resp_pkts"])
    duration = numeric(flow.get("duration", pd.Series(0.0, index=flow.index)))
    total_b = b0 + b1; total_p = p0 + p1
    proto = flow["proto"].astype(str).str.lower().str.strip()
    safe_d = duration.clip(lower=1e-3)
    out = pd.DataFrame({
        "log_total_bytes": np.log1p(total_b),
        "log_total_packets": np.log1p(total_p),
        "log_duration": np.log1p(duration),
        "response_byte_ratio": (b1 / total_b.replace(0, np.nan)).fillna(0.0),
        "response_packet_ratio": (p1 / total_p.replace(0, np.nan)).fillna(0.0),
        "tcp_flag": (proto == "tcp").astype(float),
        "udp_flag": (proto == "udp").astype(float),
        "icmp_flag": proto.str.startswith("icmp").astype(float),
        "log_bytes_per_packet": np.log1p(total_b / total_p.clip(lower=1.0)),
        "log_packets_per_second": np.log1p((total_p / safe_d).clip(upper=1e8)),
        "log_bytes_per_second": np.log1p((total_b / safe_d).clip(upper=1e12)),
    })
    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def metric(y, score, threshold):
    y = np.asarray(y, dtype=np.int8); score = np.asarray(score, dtype=float)
    pred = score >= float(threshold); pos = y == 1; neg = ~pos
    tp = int(np.sum(pred & pos)); fn = int(np.sum((~pred) & pos))
    fp = int(np.sum(pred & neg)); tn = int(np.sum((~pred) & neg))
    recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "support": int(len(y)), "positives": int(pos.sum()), "negatives": int(neg.sum()),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "threshold": float(threshold), "recall": float(recall), "fpr": float(fpr),
        "precision": float(precision), "f1": float(f1),
        "pr_auc": float(average_precision_score(y, score)) if len(np.unique(y)) > 1 else None,
        "roc_auc": float(roc_auc_score(y, score)) if len(np.unique(y)) > 1 else None,
    }


def threshold_at_fpr(y, score, budget=CAL_FPR_TARGET):
    y = np.asarray(y, dtype=np.int8); score = np.asarray(score, dtype=float)
    neg = np.sort(score[y == 0])
    if len(neg) < 100:
        raise RuntimeError(f"Need >=100 benign calibration rows, got {len(neg)}")
    k = int(math.floor(float(budget) * len(neg)))
    if k <= 0:
        return float(np.nextafter(neg[-1], np.inf))
    return float(np.nextafter(neg[-k], np.inf))


def deterministic_cap(X, y, max_per_class, salt):
    y = np.asarray(y, dtype=np.int8)
    rng = np.random.default_rng(SEED + int(salt))
    take = []
    for cls in (0, 1):
        ids = np.where(y == cls)[0]
        if len(ids) > max_per_class:
            ids = np.sort(rng.choice(ids, size=max_per_class, replace=False))
        take.append(ids)
    ids = np.sort(np.concatenate(take))
    return X[ids], y[ids]


def class_order_threeway(flow: pd.DataFrame):
    y = flow["y"].to_numpy(dtype=np.int8)
    out = {"fit": [], "cal": [], "eval": []}
    for cls in (0, 1):
        ids = np.where(y == cls)[0]
        n = len(ids)
        if n < 300:
            raise RuntimeError(f"Development source class {cls} too small for 3-way split: {n}")
        a = max(1, int(0.60 * n)); b = max(a + 1, int(0.80 * n))
        out["fit"].append(ids[:a]); out["cal"].append(ids[a:b]); out["eval"].append(ids[b:])
    return {k: np.sort(np.concatenate(v)) for k, v in out.items()}


def arrays_for_flow(flow: pd.DataFrame, split_ids: dict):
    pf = portable_frame(flow)
    y = flow["y"].to_numpy(dtype=np.int8)
    out = {}
    for part, ids in split_ids.items():
        out[part] = {"y": y[ids]}
        for view, cols in FEATURE_VIEWS.items():
            out[part][view] = pf.iloc[ids][cols].to_numpy(dtype=np.float32)
    return out


def unsw_feature_names(root: Path, shard: Path):
    probe = pd.read_csv(shard, header=None, nrows=1)
    defs = sorted(root.rglob("*features*.csv")) + sorted(root.rglob("*Features*.csv"))
    if not defs:
        raise RuntimeError("UNSW feature definition missing")
    return read_feature_names(defs[0], int(probe.shape[1]))


def load_unsw_development(root: Path):
    shards = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if len(shards) != 4:
        raise RuntimeError(f"Expected 4 UNSW raw shards, got {shards}")
    names = unsw_feature_names(root, shards[0])
    parts = {"fit": {v: [] for v in FEATURE_VIEWS}, "cal": {v: [] for v in FEATURE_VIEWS}, "eval": {v: [] for v in FEATURE_VIEWS}}
    ys = {"fit": [], "cal": [], "eval": []}; audit = []
    for i, path in enumerate(shards):
        flow = load_unsw_shard(path, names)
        pf = portable_frame(flow); y = flow["y"].to_numpy(dtype=np.int8)
        part = "fit" if i < 2 else ("cal" if i == 2 else "eval")
        ys[part].append(y)
        for view, cols in FEATURE_VIEWS.items():
            parts[part][view].append(pf[cols].to_numpy(dtype=np.float32))
        audit.append({"file": path.name, "sha256": sha256(path), "rows": int(len(y)), "part": part,
                      "positives": int(y.sum()), "negatives": int((y == 0).sum())})
        del flow, pf
    out = {}
    for part in ("fit", "cal", "eval"):
        out[part] = {"y": np.concatenate(ys[part])}
        for view in FEATURE_VIEWS:
            out[part][view] = np.concatenate(parts[part][view], axis=0)
    return out, audit


def load_iot23_development(malicious: Path, benign: Path, freeze_iot23: Path):
    f = json.loads(freeze_iot23.read_text())
    mal_host = f["malicious_capture"]["host_ip"]; ben_host = f["benign_capture"]["host_ip"]
    mal = read_zeek_labeled_whitespace(malicious, mal_host)
    ben = read_zeek_labeled_whitespace(benign, ben_host)
    cols = ["ts", "src", "dst", "dport", "proto", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "y"]
    flow = pd.concat([ben[cols], mal[cols]], ignore_index=True)
    split = class_order_threeway(flow)
    out = arrays_for_flow(flow, split)
    audit = {
        "malicious_file": malicious.name, "malicious_sha256": sha256(malicious),
        "benign_file": benign.name, "benign_sha256": sha256(benign),
        "rows": int(len(flow)), "positives": int(flow["y"].sum()), "negatives": int((flow["y"] == 0).sum()),
        "split": {k: int(len(v)) for k, v in split.items()},
    }
    return out, audit


def load_rtiot_canonical(path: Path):
    df = pd.read_csv(path, low_memory=False)
    m = {norm(c): c for c in df.columns}
    c_label = pick(m, "Attack_type", "attacktype")
    c_proto = pick(m, "proto", "protocol")
    c_fpk = pick(m, "fwd_pkts_tot", "fwdpktstot", "totfwdpkts")
    c_bpk = pick(m, "bwd_pkts_tot", "bwdpktstot", "totbwdpkts")
    c_fb = pick(m, "fwd_pkts_payload.tot", "fwdpktspayloadtot", "totlenfwdpkts")
    c_bb = pick(m, "bwd_pkts_payload.tot", "bwdpktspayloadtot", "totlenbwdpkts")
    c_dur = pick(m, "flow_duration", "flowduration", "duration")
    required = [c_label, c_proto, c_fpk, c_bpk, c_fb, c_bb]
    if any(v is None for v in required):
        raise RuntimeError(f"RT-IoT2022 canonical columns unresolved: columns={list(df.columns)}")
    text = df[c_label].astype(str).str.strip(); ln = text.map(norm)
    normal = ln.map(lambda x: x.startswith("mqtt") or x.startswith("thingspeak") or x.startswith("wiprob") or x.startswith("wiprobulb"))
    y = (~normal).astype(np.int8)
    return pd.DataFrame({
        "duration": 0.0 if c_dur is None else df[c_dur],
        "orig_bytes": df[c_fb], "resp_bytes": df[c_bb], "orig_pkts": df[c_fpk], "resp_pkts": df[c_bpk],
        "proto": df[c_proto], "y": y,
    })


def load_rtiot_development(path: Path):
    flow = load_rtiot_canonical(path)
    split = class_order_threeway(flow); out = arrays_for_flow(flow, split)
    audit = {"file": path.name, "sha256": sha256(path), "rows": int(len(flow)),
             "positives": int(flow["y"].sum()), "negatives": int((flow["y"] == 0).sum()),
             "split": {k: int(len(v)) for k, v in split.items()}}
    return out, audit


def candidates():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(C=0.35, class_weight=None, max_iter=4000, solver="lbfgs", random_state=SEED)),
        ]),
        "histgb": HistGradientBoostingClassifier(
            learning_rate=0.05, max_iter=260, max_leaf_nodes=15, min_samples_leaf=30,
            l2_regularization=5.0, class_weight=None, random_state=SEED,
        ),
    }


def source_class_weights(source_y):
    weights = []
    for y in source_y:
        y = np.asarray(y, dtype=np.int8); w = np.zeros(len(y), dtype=float)
        for cls in (0, 1):
            n = max(int(np.sum(y == cls)), 1)
            w[y == cls] = 1.0 / (2.0 * n)
        weights.append(w)
    # Equal total mass per source; then normalize global mean weight to 1.
    w = np.concatenate(weights)
    w *= len(w) / max(float(w.sum()), 1e-12)
    return w


def fit_model(kind, X, y, sample_weight):
    model = candidates()[kind]
    if kind == "logistic":
        model.fit(X, y, clf__sample_weight=sample_weight)
    else:
        model.fit(X, y, sample_weight=sample_weight)
    return model


def prepare(args):
    freeze = Path(args.freeze); f = json.loads(freeze.read_text())
    if f.get("created_before_toniot_file_access") is not True:
        raise RuntimeError("V92 freeze is not pre-access")
    for key in ("external_source_used_for_fit", "external_source_used_for_feature_selection",
                "external_source_used_for_model_selection", "external_source_used_for_threshold_selection",
                "external_metrics_used_for_any_selection"):
        if f.get(key) is not False:
            raise RuntimeError(f"V92 freeze contract invalid: {key}")
    out = Path(args.bundle)
    if out.exists():
        raise RuntimeError("Bundle path exists; V92 prepare is immutable")
    out.mkdir(parents=True)

    unsw, unsw_audit = load_unsw_development(Path(args.unsw_root))
    iot23, iot23_audit = load_iot23_development(Path(args.iot23_malicious), Path(args.iot23_benign), Path(args.iot23_freeze))
    rtiot, rtiot_audit = load_rtiot_development(Path(args.rtiot))
    sources = {"UNSW-NB15": unsw, "IoT-23": iot23, "RT-IoT2022": rtiot}

    rows = []; fitted = {}
    for view in FEATURE_VIEWS:
        for kind in candidates():
            fit_x, fit_y = [], []
            for si, (source, d) in enumerate(sources.items()):
                X, y = deterministic_cap(d["fit"][view], d["fit"]["y"], MAX_FIT_PER_SOURCE_CLASS, 100 * si + 1)
                fit_x.append(X); fit_y.append(y)
            Xfit = np.concatenate(fit_x); yfit = np.concatenate(fit_y)
            weights = source_class_weights(fit_y)
            model = fit_model(kind, Xfit, yfit, weights)

            source_cal_thresholds = {}; cal_metrics = {}
            for si, (source, d) in enumerate(sources.items()):
                Xc, yc = deterministic_cap(d["cal"][view], d["cal"]["y"], MAX_CAL_PER_SOURCE_CLASS, 100 * si + 2)
                score = np.asarray(model.predict_proba(Xc)[:, 1], dtype=float)
                t = threshold_at_fpr(yc, score, CAL_FPR_TARGET)
                source_cal_thresholds[source] = float(t)
                cal_metrics[source] = metric(yc, score, t)
            threshold = max(source_cal_thresholds.values())

            ev = {}; fprs = []; recalls = []; f1s = []
            for si, (source, d) in enumerate(sources.items()):
                Xe, ye = deterministic_cap(d["eval"][view], d["eval"]["y"], MAX_EVAL_PER_SOURCE_CLASS, 100 * si + 3)
                score = np.asarray(model.predict_proba(Xe)[:, 1], dtype=float)
                m = metric(ye, score, threshold); ev[source] = m
                fprs.append(m["fpr"]); recalls.append(m["recall"]); f1s.append(m["f1"])
            feasible = bool(max(fprs) <= FPR_GATE + 1e-12)
            row = {
                "feature_view": view, "model": kind, "fixed_threshold": float(threshold),
                "calibration_fpr_target": CAL_FPR_TARGET,
                "source_specific_calibration_thresholds": source_cal_thresholds,
                "calibration_metrics_at_source_thresholds": cal_metrics,
                "development_evaluation": ev,
                "max_source_fpr": float(max(fprs)), "min_source_recall": float(min(recalls)),
                "min_source_f1": float(min(f1s)), "mean_source_f1": float(np.mean(f1s)),
                "meets_all_development_1pct_fpr": feasible,
            }
            rows.append(row); fitted[(view, kind)] = model
            print("V92 DEV CANDIDATE", json.dumps(row, indent=2), flush=True)

    feasible = [r for r in rows if r["meets_all_development_1pct_fpr"]]
    if not feasible:
        raise RuntimeError("No V92 development candidate satisfies <=1% FPR on every development source; ToN-IoT remains unopened")
    feasible.sort(key=lambda r: (r["min_source_f1"], r["min_source_recall"], r["mean_source_f1"], -r["max_source_fpr"]), reverse=True)
    winner = feasible[0]
    model = fitted[(winner["feature_view"], winner["model"])]
    model_path = out / "selected_model.joblib"; joblib.dump(model, model_path)
    pre = {
        "protocol": "V92 multi-domain pretest freeze before ToN-IoT access",
        "freeze_sha256": sha256(freeze), "features": FEATURE_VIEWS,
        "selected": winner, "all_candidates": rows,
        "development_source_audit": {"UNSW-NB15": unsw_audit, "IoT-23": iot23_audit, "RT-IoT2022": rtiot_audit},
        "model_file": model_path.name, "model_sha256": sha256(model_path),
        "external_source_opened": False,
        "external_metrics_used_for_selection": False,
    }
    pp = out / "pretest_model_selection.json"
    pp.write_text(json.dumps(pre, indent=2, allow_nan=False) + "\n")
    print("V92 PRETEST SEALED", json.dumps({"pretest_sha256": sha256(pp), "model_sha256": sha256(model_path), "selected": winner}, indent=2), flush=True)


def load_toniot(path: Path):
    df = pd.read_csv(path, low_memory=False)
    m = {norm(c): c for c in df.columns}
    c_label = pick(m, "label"); c_type = pick(m, "type", "attack_type", "attacktype")
    c_proto = pick(m, "proto", "protocol")
    c_dur = pick(m, "duration", "dur")
    c_sb = pick(m, "src_bytes", "srcbytes", "sbytes")
    c_db = pick(m, "dst_bytes", "dstbytes", "dbytes")
    c_sp = pick(m, "src_pkts", "srcpkts", "spkts")
    c_dp = pick(m, "dst_pkts", "dstpkts", "dpkts")
    required = {"label": c_label, "proto": c_proto, "duration": c_dur, "src_bytes": c_sb,
                "dst_bytes": c_db, "src_pkts": c_sp, "dst_pkts": c_dp}
    missing = [k for k, v in required.items() if v is None]
    if missing:
        raise RuntimeError(f"ToN-IoT public-schema fields unresolved: {missing}; columns={list(df.columns)}")
    y = pd.to_numeric(df[c_label], errors="coerce").fillna(0).astype(np.int8).clip(0, 1).to_numpy()
    types = df[c_type].astype(str).str.strip().to_numpy() if c_type else np.where(y == 1, "attack", "normal")
    flow = pd.DataFrame({"duration": df[c_dur], "orig_bytes": df[c_sb], "resp_bytes": df[c_db],
                         "orig_pkts": df[c_sp], "resp_pkts": df[c_dp], "proto": df[c_proto], "y": y})
    return flow, types


def score(args):
    freeze = Path(args.freeze); f = json.loads(freeze.read_text())
    bundle = Path(args.bundle); pp = bundle / "pretest_model_selection.json"; mp = bundle / "selected_model.joblib"
    pre = json.loads(pp.read_text())
    if pre.get("external_source_opened") is not False or pre.get("external_metrics_used_for_selection") is not False:
        raise RuntimeError("Pretest manifest contaminated")
    if pre.get("freeze_sha256") != sha256(freeze):
        raise RuntimeError("Freeze hash mismatch")
    if pre.get("model_sha256") != sha256(mp):
        raise RuntimeError("Model hash mismatch")
    # First test-file read occurs only after all frozen bundle checks above.
    test = Path(args.toniot)
    flow, types = load_toniot(test)
    selected = pre["selected"]; view = selected["feature_view"]; threshold = float(selected["fixed_threshold"])
    model = joblib.load(mp)
    X = portable_frame(flow)[FEATURE_VIEWS[view]].to_numpy(dtype=np.float32)
    y = flow["y"].to_numpy(dtype=np.int8)
    score = np.asarray(model.predict_proba(X)[:, 1], dtype=float)
    overall = metric(y, score, threshold)
    per_type = {}
    for lab in sorted(set(types.tolist())):
        mask = types == lab; yy = y[mask]; ss = score[mask]; pred = ss >= threshold
        target = "attack" if float(yy.mean()) >= 0.5 else "benign"
        per_type[str(lab)] = {
            "support": int(mask.sum()), "binary_target": target, "alert_rate": float(pred.mean()),
            "recall_if_attack": float(pred.mean()) if target == "attack" else None,
            "fpr_if_benign": float(pred.mean()) if target == "benign" else None,
        }
    gate = bool(overall["recall"] >= RECALL_GATE and overall["fpr"] <= FPR_GATE + 1e-12)
    report = {
        "protocol": "V92 first untouched ToN-IoT external one-shot transfer",
        "claim_boundary": f["claim_boundary"],
        "freeze_sha256": sha256(freeze), "pretest_model_selection_sha256": sha256(pp),
        "model_sha256": sha256(mp), "external_test_file_sha256": sha256(test),
        "selected_model": selected, "external_rows": int(len(y)),
        "external_metrics": overall, "per_type": per_type,
        "external_gate": {"recall_at_least_80pct": bool(overall["recall"] >= RECALL_GATE),
                          "fpr_at_most_1pct": bool(overall["fpr"] <= FPR_GATE + 1e-12),
                          "passed": gate},
        "no_test_tuning_contract": {
            "freeze_committed_before_test_access": bool(f["created_before_toniot_file_access"]),
            "pretest_model_manifest_written_before_test_read": True,
            "test_metrics_used_for_features": False,
            "test_metrics_used_for_model_selection": False,
            "test_metrics_used_for_threshold_selection": False,
            "test_rows_removed_after_predictions": False,
            "model_refit_after_test_read": False,
        },
    }
    out = Path(args.output)
    if out.exists():
        raise RuntimeError("V92 external output exists; first result is immutable")
    out.mkdir(parents=True)
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("V92 TONIOT FIRST EXTERNAL RESULT", json.dumps({"external_metrics": overall, "external_gate": report["external_gate"], "per_type": per_type}, indent=2), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--unsw-root", required=True); p.add_argument("--iot23-malicious", required=True)
    p.add_argument("--iot23-benign", required=True); p.add_argument("--iot23-freeze", required=True)
    p.add_argument("--rtiot", required=True); p.add_argument("--freeze", required=True); p.add_argument("--bundle", required=True)
    s = sub.add_parser("score")
    s.add_argument("--freeze", required=True); s.add_argument("--bundle", required=True)
    s.add_argument("--toniot", required=True); s.add_argument("--output", required=True)
    args = ap.parse_args()
    prepare(args) if args.command == "prepare" else score(args)


if __name__ == "__main__":
    main()
