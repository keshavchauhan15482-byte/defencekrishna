"""V21 development experiment for unseen-family future forecasting.

Adds only family-agnostic network microstructure features plus a benign OOD head:
request concentration, destination/port churn, entropy, inter-arrival dynamics,
and short-window acceleration. Frozen final-validation families are never scored.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score
from sklearn.preprocessing import StandardScaler

import v16_xiiotid_unseen_forecast as base
import v19_dev_highres_tree as v19

WINDOW_SECONDS = 30
HISTORY_WINDOWS = 16
FUTURE_WINDOWS = 8
OUT = Path("artifacts/v21_dev")
OUT.mkdir(parents=True, exist_ok=True)
ALPHAS = (0.0, 0.25, 0.5, 0.75, 1.0)


def _entropy(values):
    vc = pd.Series(values).value_counts(dropna=False).to_numpy(dtype=float)
    if len(vc) <= 1:
        return 0.0
    p = vc / vc.sum()
    h = -np.sum(p * np.log(np.maximum(p, 1e-12)))
    return float(h / np.log(len(vc)))


def _top_share(values):
    vc = pd.Series(values).value_counts(dropna=False)
    return float(vc.iloc[0] / vc.sum()) if len(vc) else 0.0


def build_state(df, dt, y, family_col, binary_col, date_col, ts_col):
    src_col = base.pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    dst_col = base.pick_col(df.columns, ["Des_IP", "Dst_IP", "Destination_IP", "dst_ip"])
    dport_col = base.pick_col(df.columns, ["Des_port", "Dst_port", "Destination_port", "dst_port"])
    proto_col = base.pick_col(df.columns, ["Protocol", "Proto"])
    service_col = base.pick_col(df.columns, ["Service", "Serv"])
    conn_col = base.pick_col(df.columns, ["Conn_state", "Connection_state", "State"])
    excluded = {x for x in [family_col, binary_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if base.norm(c) in {"class1", "class2", "class3"})
    numeric, audit = base.strict_network_features(df, excluded)

    f = pd.DataFrame({
        "dt": dt,
        "y": y,
        "family": df[family_col].astype(str).map(base.norm_label),
        "src": df[src_col].astype(str) if src_col else "GLOBAL",
    })
    if dst_col:
        f["dst"] = df[dst_col].astype(str)
    if dport_col:
        f["dport"] = df[dport_col].astype(str)
    if conn_col:
        f["conncat"] = df[conn_col].fillna("__missing__").astype(str)
    for c in numeric:
        f[c] = base.numericize(df[c])

    cats = []
    for prefix, col in (("proto", proto_col), ("service", service_col)):
        if col:
            b = df[col].fillna("__missing__").astype(str).map(v19.bucket).to_numpy()
            for k in range(v19.HASH_BUCKETS):
                name = f"{prefix}_b{k}"
                f[name] = (b == k).astype(np.float32)
                cats.append(name)

    f = f.dropna(subset=["dt", "y"]).copy()
    f = f.sort_values(["src", "dt"]).reset_index(drop=True)
    f["iat"] = f.groupby("src", sort=False)["dt"].diff().dt.total_seconds().clip(lower=0, upper=300)
    f["bin"] = f["dt"].dt.floor(f"{WINDOW_SECONDS}s")
    f["y"] = f["y"].astype(int)
    if dst_col and dport_col:
        f["pair"] = f["dst"].astype(str) + ":" + f["dport"].astype(str)

    g = f.groupby(["src", "bin"], sort=True)
    s = g[numeric].agg(["mean", "std", "max"])
    s.columns = ["__".join(x) for x in s.columns]
    if cats:
        s = s.join(g[cats].mean())
    s["flow_count"] = g.size().astype(float)
    s["iat_mean"] = g["iat"].mean()
    s["iat_std"] = g["iat"].std()
    s["iat_min"] = g["iat"].min()
    s["attack_now"] = g["y"].max().astype(int)
    s["family_now"] = g["family"].agg(lambda x: tuple(sorted({base.norm_label(v) for v in x if base.norm_label(v) != "normal"})))

    if dst_col:
        s["unique_dst"] = g["dst"].nunique().astype(float)
        s["dst_top_share"] = g["dst"].agg(_top_share)
        s["dst_entropy"] = g["dst"].agg(_entropy)
    if dport_col:
        s["unique_dst_port"] = g["dport"].nunique().astype(float)
        s["port_top_share"] = g["dport"].agg(_top_share)
        s["port_entropy"] = g["dport"].agg(_entropy)
    if dst_col and dport_col:
        s["unique_dst_port_pairs"] = g["pair"].nunique().astype(float)
    if conn_col:
        s["conn_state_entropy"] = g["conncat"].agg(_entropy)
        s["conn_state_top_share"] = g["conncat"].agg(_top_share)

    s["flows_per_dst"] = s["flow_count"] / np.maximum(s.get("unique_dst", 1.0), 1.0)
    s["flows_per_port"] = s["flow_count"] / np.maximum(s.get("unique_dst_port", 1.0), 1.0)
    s["pair_repetition"] = s["flow_count"] / np.maximum(s.get("unique_dst_port_pairs", 1.0), 1.0)
    s = s.reset_index().sort_values(["src", "bin"]).reset_index(drop=True)
    fcols = [c for c in s.columns if c not in ["src", "bin", "attack_now", "family_now"]]
    return s, fcols, numeric, cats, {
        "source_ip": src_col,
        "destination_ip": dst_col,
        "destination_port": dport_col,
        "protocol": proto_col,
        "service": service_col,
        "connection_state": conn_col,
        "strict_network_audit": audit,
    }


def robust_ood_fit(Z, benign_idx):
    b = Z[benign_idx].astype(np.float64)
    med = np.median(b, axis=0)
    mad = np.median(np.abs(b - med), axis=0)
    scale = np.maximum(1.4826 * mad, 0.15)
    return med, scale


def robust_ood_score(Z, med, scale):
    z = np.abs((Z - med) / scale)
    k = min(12, z.shape[1])
    top = np.partition(z, z.shape[1] - k, axis=1)[:, -k:]
    return np.mean(top, axis=1)


def percentile_from_ref(ref, values):
    r = np.sort(np.asarray(ref, dtype=float))
    return np.searchsorted(r, values, side="right") / max(1, len(r))


def calibrator(raw_p, y):
    p = np.clip(raw_p, 1e-6, 1 - 1e-6)
    x = np.log(p / (1 - p)).reshape(-1, 1)
    m = LogisticRegression(C=1e6, max_iter=300)
    m.fit(x, y)
    return m


def apply_cal(m, p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return m.predict_proba(np.log(p / (1 - p)).reshape(-1, 1))[:, 1]


def threshold_from_policy(y, p, budget):
    benign = p[y == 0]
    return float(np.quantile(benign, 1 - budget, method="higher"))


def metrics(y, p, th, clean_pos=None):
    pred = p >= th
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    d = {
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else None,
        "threshold": float(th),
    }
    if clean_pos is not None:
        d["clean_history_future_positive_n"] = int(clean_pos.sum())
        d["clean_history_future_positive_recall"] = float(pred[clean_pos].mean()) if clean_pos.any() else None
    return d


def run_family(S, target, clean, split, blocks, eligible, hist_fams, future_steps, family, seed):
    future = v19.family_mask(future_steps, family)
    exposed = future | v19.history_mask(hist_fams, family)
    held = set(int(x) for x in np.unique(blocks[eligible & exposed]))

    def safe(name):
        idx = split[name]
        keep = np.asarray([(int(blocks[i]) not in held) and not exposed[i] for i in idx])
        return idx[keep]

    tr, ca, po = safe("train"), safe("calibration"), safe("policy")
    for name, idx in (("train", tr), ("calibration", ca), ("policy", po)):
        c = np.bincount(target[idx], minlength=2)
        if c.min() < 20:
            raise RuntimeError(f"{family}: {name} support {c.tolist()}")

    rng = np.random.default_rng(seed)
    if len(tr) > 80000:
        tr = rng.choice(tr, 80000, replace=False)
    med = np.nanmedian(S[tr].astype(np.float64), axis=0)
    med[~np.isfinite(med)] = 0
    Z = S.astype(np.float32, copy=True)
    bad = ~np.isfinite(Z)
    Z[bad] = med[np.where(bad)[1]].astype(np.float32)
    scaler = StandardScaler().fit(Z[tr])
    ZA = scaler.transform(Z)

    model = HistGradientBoostingClassifier(
        max_iter=350, learning_rate=.05, max_leaf_nodes=31,
        min_samples_leaf=20, l2_regularization=1.5,
        class_weight="balanced", random_state=seed,
    )
    model.fit(ZA[tr], target[tr])
    cal = calibrator(model.predict_proba(ZA[ca])[:, 1], target[ca])
    psup = apply_cal(cal, model.predict_proba(ZA)[:, 1])

    benign_tr = tr[target[tr] == 0]
    ood_med, ood_scale = robust_ood_fit(ZA, benign_tr)
    ood_raw = robust_ood_score(ZA, ood_med, ood_scale)
    pood = percentile_from_ref(ood_raw[benign_tr], ood_raw)

    allidx = np.where(eligible)[0]
    posidx = allidx[future[allidx]]
    negbase = split["test"]
    negidx = negbase[np.asarray([(int(blocks[i]) not in held) and clean[i] and target[i] == 0 for i in negbase])]
    if len(posidx) < 10 or len(negidx) < 100:
        raise RuntimeError(f"{family}: test support pos={len(posidx)} neg={len(negidx)}")
    ev = np.concatenate([posidx, negidx])
    yev = np.concatenate([np.ones(len(posidx), int), np.zeros(len(negidx), int)])
    cp = np.concatenate([clean[posidx], np.zeros(len(negidx), bool)])

    curves = {}
    for budget in v19.POLICY_FPR_BUDGETS:
        best = None
        for alpha in ALPHAS:
            score_po = alpha * psup[po] + (1.0 - alpha) * pood[po]
            th = threshold_from_policy(target[po], score_po, budget)
            pm = metrics(target[po], score_po, th)
            cand = (pm["recall"], -pm["fpr"], alpha, th)
            if best is None or cand > best:
                best = cand
        _, _, alpha, th = best
        score_ev = alpha * psup[ev] + (1.0 - alpha) * pood[ev]
        m = metrics(yev, score_ev, th, cp)
        m["alpha_supervised"] = float(alpha)
        m["alpha_ood"] = float(1.0 - alpha)
        curves[str(budget)] = m

    return {
        "family": family,
        "seed": seed,
        "heldout_blocks": len(held),
        "heldout_exposure_in_train_cal_policy": 0,
        "test_support": {
            "unseen_positive": int(len(posidx)),
            "clean_history_unseen_positive": int(clean[posidx].sum()),
            "clean_benign_negative": int(len(negidx)),
        },
        "budget_curve": curves,
    }


def main():
    import kagglehub

    root = Path(kagglehub.dataset_download("munaalhawawreh/xiiotid-iiot-intrusion-dataset"))
    csv_path = max(root.rglob("*.csv"), key=lambda p: p.stat().st_size)
    if base.sha256(csv_path) != "7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0":
        raise RuntimeError("source hash changed")
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, _, _ = base.parse_time(df)
    y, binary_col, _ = base.detect_binary_label(df)
    family_col = base.detect_family_col(df, binary_col)
    state, fcols, numeric, cats, cols = build_state(df, dt, y, family_col, binary_col, date_col, ts_col)

    v19.WINDOW_SECONDS = WINDOW_SECONDS
    v19.HISTORY_WINDOWS = HISTORY_WINDOWS
    v19.FUTURE_WINDOWS = FUTURE_WINDOWS
    S, target, cutoff, clean, hist, fut = v19.make_summary_sequences(state, fcols)
    split, blocks, eligible = v19.split_blocks(cutoff)

    report = {
        "schema": "krishna-v21-dev-microstructure-ood-v1",
        "purpose": "Development only. Frozen final validation families remain unscored.",
        "window_seconds": WINDOW_SECONDS,
        "history_minutes": 8,
        "future_minutes": 4,
        "development_families": v19.DEV_FAMILIES,
        "final_validation_families_not_scored": v19.FINAL_FAMILIES,
        "network_numeric": numeric,
        "network_categorical": cats,
        "columns": cols,
        "state_feature_count": len(fcols),
        "summary_feature_count": int(S.shape[1]),
        "results": {},
    }
    completed = []
    for fam in v19.DEV_FAMILIES:
        report["results"][fam] = {}
        try:
            for seed in base.SEEDS:
                print(f"V21 family={fam} seed={seed}", flush=True)
                r = run_family(S, target, clean, split, blocks, eligible, hist, fut, fam, seed)
                report["results"][fam][str(seed)] = r
                print(json.dumps(r, indent=2), flush=True)
            completed.append(fam)
        except RuntimeError as exc:
            report["results"][fam]["skipped"] = str(exc)
            print("SKIP", fam, exc, flush=True)

    if len(completed) < 3:
        raise RuntimeError(f"only {len(completed)} families completed")
    budgets = {}
    for b in v19.POLICY_FPR_BUDGETS:
        key = str(b)
        fam_metrics = []
        for fam in completed:
            fam_metrics.append({
                k: float(np.mean([report["results"][fam][str(s)]["budget_curve"][key][k] for s in base.SEEDS]))
                for k in ["fpr", "recall", "precision", "f1"]
            })
        budgets[key] = {
            "macro": {k: float(np.mean([m[k] for m in fam_metrics])) for k in fam_metrics[0]},
            "per_family": {fam: fam_metrics[i] for i, fam in enumerate(completed)},
        }
    feasible = [(b, v) for b, v in budgets.items() if v["macro"]["fpr"] <= 0.02]
    chosen = max(feasible, key=lambda x: x[1]["macro"]["recall"]) if feasible else min(budgets.items(), key=lambda x: x[1]["macro"]["fpr"])
    report["budget_results"] = budgets
    report["chosen_policy_budget"] = chosen[0]
    report["macro_mean"] = chosen[1]["macro"]
    report["development_target"] = {
        "target_macro_fpr": 0.02,
        "target_macro_unseen_recall": 0.80,
        "macro_fpr_pass": chosen[1]["macro"]["fpr"] <= 0.02,
        "macro_recall_pass": chosen[1]["macro"]["recall"] >= 0.80,
        "all_family_recall_ge_0_80": all(m["recall"] >= 0.80 for m in chosen[1]["per_family"].values()),
        "ready_to_unlock_frozen_final_validation": bool(
            chosen[1]["macro"]["fpr"] <= 0.02
            and chosen[1]["macro"]["recall"] >= 0.80
            and all(m["recall"] >= 0.80 for m in chosen[1]["per_family"].values())
        ),
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2))
    (OUT / "REPORT.md").write_text(
        "# V21 generic microstructure + benign OOD development\n\n"
        + "Frozen final families were not scored.\n\n```json\n"
        + json.dumps({
            "chosen_policy_budget": report["chosen_policy_budget"],
            "macro_mean": report["macro_mean"],
            "development_target": report["development_target"],
        }, indent=2)
        + "\n```\n"
    )
    print("V21_FINAL", json.dumps({"macro": report["macro_mean"], "gate": report["development_target"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
