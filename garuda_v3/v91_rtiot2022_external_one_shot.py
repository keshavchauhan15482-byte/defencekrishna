"""V91 sealed RT-IoT2022 second-source one-shot benchmark.

The IoT-23 V89 result exposed domain dependence in absolute host-minute traffic scale.
V91 therefore precommits a smaller domain-portable per-flow representation containing
only packet/byte totals, response ratios, protocol indicators and bytes-per-packet.
Model, feature view and <=1% FPR threshold are selected exclusively on UNSW-NB15.
RT-IoT2022 is opened only after that pretest manifest is written and hashed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v59_unsw_independent_replication import norm, read_feature_names
from .v89_iot23_external_one_shot import sha256, metric, threshold_at_fpr, load_unsw_shard

FEATURES = [
    "log_total_bytes", "log_total_packets", "response_byte_ratio",
    "response_packet_ratio", "tcp_flag", "udp_flag", "icmp_flag",
    "log_bytes_per_packet",
]
FPR_BUDGET = 0.01
SEED = 9101
MAX_TRAIN_PER_CLASS = 300000


def portable_features(flow: pd.DataFrame) -> pd.DataFrame:
    b0 = pd.to_numeric(flow["orig_bytes"], errors="coerce").fillna(0).clip(lower=0)
    b1 = pd.to_numeric(flow["resp_bytes"], errors="coerce").fillna(0).clip(lower=0)
    p0 = pd.to_numeric(flow["orig_pkts"], errors="coerce").fillna(0).clip(lower=0)
    p1 = pd.to_numeric(flow["resp_pkts"], errors="coerce").fillna(0).clip(lower=0)
    total_b = b0 + b1
    total_p = p0 + p1
    proto = flow["proto"].astype(str).str.lower().str.strip()
    out = pd.DataFrame({
        "log_total_bytes": np.log1p(total_b),
        "log_total_packets": np.log1p(total_p),
        "response_byte_ratio": (b1 / total_b.replace(0, np.nan)).fillna(0),
        "response_packet_ratio": (p1 / total_p.replace(0, np.nan)).fillna(0),
        "tcp_flag": (proto == "tcp").astype(float),
        "udp_flag": (proto == "udp").astype(float),
        "icmp_flag": proto.str.startswith("icmp").astype(float),
        "log_bytes_per_packet": np.log1p(total_b / total_p.clip(lower=1)),
    })
    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def unsw_names(root: Path, shard: Path):
    probe = pd.read_csv(shard, header=None, nrows=1)
    feature_files = sorted(root.rglob("*features*.csv")) + sorted(root.rglob("*Features*.csv"))
    if not feature_files:
        raise RuntimeError("UNSW feature definition missing")
    return read_feature_names(feature_files[0], int(probe.shape[1]))


def balanced_cap(X, y, per_class=MAX_TRAIN_PER_CLASS):
    rng = np.random.default_rng(SEED)
    ids = []
    for cls in (0, 1):
        idx = np.where(y == cls)[0]
        if len(idx) > per_class:
            idx = np.sort(rng.choice(idx, size=per_class, replace=False))
        ids.append(idx)
    take = np.concatenate(ids)
    return X[take], y[take]


def load_unsw(root: Path):
    shards = sorted(root.rglob("UNSW-NB15_[1-4].csv"))
    if len(shards) != 4:
        raise RuntimeError(f"Expected four UNSW shards, got {shards}")
    names = unsw_names(root, shards[0])
    X_parts, y_parts, audit = [], [], []
    for i, p in enumerate(shards):
        flow = load_unsw_shard(p, names)
        X = portable_features(flow).to_numpy(dtype=np.float32)
        y = flow["y"].to_numpy(dtype=np.int8)
        audit.append({"shard": p.name, "sha256": sha256(p), "rows": int(len(y)),
                      "positives": int(y.sum()), "negatives": int((y == 0).sum())})
        if i < 3:
            X_parts.append(X); y_parts.append(y)
        else:
            Xv, yv = X, y
    Xtr = np.concatenate(X_parts); ytr = np.concatenate(y_parts)
    Xtr, ytr = balanced_cap(Xtr, ytr)
    return Xtr, ytr, Xv, yv, audit


def candidates():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(C=0.35, class_weight="balanced", max_iter=3000,
                                       solver="lbfgs", random_state=SEED)),
        ]),
        "histgb": HistGradientBoostingClassifier(
            learning_rate=0.05, max_iter=220, max_leaf_nodes=15,
            min_samples_leaf=30, l2_regularization=5.0,
            class_weight="balanced", random_state=SEED,
        ),
    }


def select_unsw(Xtr, ytr, Xv, yv):
    rows, models = [], {}
    for name, model in candidates().items():
        model.fit(Xtr, ytr)
        score = np.asarray(model.predict_proba(Xv)[:, 1], dtype=float)
        t = threshold_at_fpr(yv, score, FPR_BUDGET)
        row = {"model": name, **metric(yv, score, t)}
        rows.append(row); models[name] = model
    feasible = [r for r in rows if r["fpr"] <= FPR_BUDGET + 1e-12]
    if not feasible:
        feasible = rows
    feasible.sort(key=lambda r: (r["recall"], r["precision"], r["pr_auc"] or 0.0), reverse=True)
    w = feasible[0]
    return models[w["model"]], float(w["threshold"]), w, rows


def pick(mapping, *names):
    for n in names:
        k = norm(n)
        if k in mapping:
            return mapping[k]
    return None


def load_rtiot(path: Path):
    df = pd.read_csv(path, low_memory=False)
    m = {norm(c): c for c in df.columns}
    c_label = pick(m, "Attack_type", "attacktype")
    c_proto = pick(m, "proto", "protocol")
    c_fpk = pick(m, "fwd_pkts_tot", "fwdpktstot")
    c_bpk = pick(m, "bwd_pkts_tot", "bwdpktstot")
    c_fb = pick(m, "fwd_pkts_payload.tot", "fwdpktspayloadtot")
    c_bb = pick(m, "bwd_pkts_payload.tot", "bwdpktspayloadtot")
    required = {"label": c_label, "proto": c_proto, "fwd_pkts": c_fpk,
                "bwd_pkts": c_bpk, "fwd_bytes": c_fb, "bwd_bytes": c_bb}
    missing = [k for k, v in required.items() if v is None]
    if missing:
        raise RuntimeError(f"RT-IoT2022 required columns unresolved: {missing}; columns={list(df.columns)}")
    label_text = df[c_label].astype(str).str.strip()
    label_norm = label_text.map(norm)
    normal = label_norm.map(lambda x: x.startswith("mqtt") or x.startswith("thingspeak") or x.startswith("wiprob") or x.startswith("wiprobulb"))
    y = (~normal).astype(np.int8).to_numpy()
    flow = pd.DataFrame({
        "orig_bytes": df[c_fb], "resp_bytes": df[c_bb],
        "orig_pkts": df[c_fpk], "resp_pkts": df[c_bpk],
        "proto": df[c_proto],
    })
    X = portable_features(flow).to_numpy(dtype=np.float32)
    return X, y, label_text.to_numpy(), {
        "rows": int(len(df)), "positives": int(y.sum()), "negatives": int((y == 0).sum()),
        "labels": {str(k): int(v) for k, v in label_text.value_counts().to_dict().items()},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--unsw-root", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--rtiot", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = Path(args.output)
    if out.exists(): ap.error("Output exists; V91 evidence is immutable")
    out.mkdir(parents=True)
    freeze = Path(args.freeze); f = json.loads(freeze.read_text())
    if f.get("selection_uses_test_metrics") is not False or f.get("fit_on_rtiot2022") is not False:
        raise RuntimeError("V91 freeze contract invalid")

    Xtr, ytr, Xv, yv, audit = load_unsw(Path(args.unsw_root))
    model, threshold, winner, rows = select_unsw(Xtr, ytr, Xv, yv)
    pre = {
        "protocol": "V91 pretest portable-flow model freeze",
        "features": FEATURES, "train_rows_after_balanced_cap": int(len(ytr)),
        "training_source": "UNSW-NB15 shards 1-3", "selection_source": "UNSW-NB15 shard 4",
        "source_audit": audit, "winner": winner, "all_candidates": rows,
        "test_metrics_used_for_selection": False,
    }
    pp = out / "pretest_model_selection.json"
    pp.write_text(json.dumps(pre, indent=2, allow_nan=False) + "\n")
    pre_sha = sha256(pp)
    print("V91 PRETEST FROZEN", json.dumps({"sha256": pre_sha, "winner": winner}, indent=2), flush=True)

    # First access to sealed second-source test occurs only after pretest manifest exists.
    rtiot = Path(args.rtiot)
    X, y, labels, ext_audit = load_rtiot(rtiot)
    score = np.asarray(model.predict_proba(X)[:, 1], dtype=float)
    overall = metric(y, score, threshold)
    per_label = {}
    for lab in sorted(set(labels.tolist())):
        mask = labels == lab
        yy = y[mask]; ss = score[mask]
        pred = ss >= threshold
        per_label[str(lab)] = {
            "support": int(mask.sum()), "binary_target": "attack" if int(yy[0]) else "benign",
            "alert_rate": float(pred.mean()),
            "recall_if_attack": float(pred.mean()) if int(yy[0]) else None,
            "fpr_if_benign": float(pred.mean()) if not int(yy[0]) else None,
        }
    report = {
        "protocol": "V91 sealed second-source RT-IoT2022 one-shot external evaluation",
        "claim_boundary": f["claim_boundary"],
        "freeze_sha256": sha256(freeze), "pretest_model_selection_sha256": pre_sha,
        "test_file_sha256": sha256(rtiot),
        "fit_on_rtiot2022": False, "selection_uses_rtiot2022_metrics": False,
        "selected_model": winner,
        "external_audit": ext_audit,
        "external_metrics": overall,
        "per_attack_type": per_label,
        "no_test_tuning_contract": {
            "pretest_manifest_written_before_test_read": True,
            "test_metrics_used_for_features": False,
            "test_metrics_used_for_model_selection": False,
            "test_metrics_used_for_threshold_selection": False,
            "test_rows_removed_after_predictions": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("V91 EXTERNAL RESULT", json.dumps(overall, indent=2), flush=True)
    print("V91 PER ATTACK TYPE", json.dumps(per_label, indent=2), flush=True)


if __name__ == "__main__":
    main()
