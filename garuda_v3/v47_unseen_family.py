"""V47 family-disjoint open-set forecasting benchmark for X-IIoTID.

Purpose
-------
Measure whether a temporal world model can warn on an attack family that was never
present in training, state validation, benign-reference fitting, or policy threshold
selection.  This is an *unseen-family simulation*, not proof of a real zero-day.

Runtime evidence is restricted to an explicit allow-list of network-traffic numeric
features.  Attack-family labels are used only to construct the frozen split and score
results; they are never model inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

HISTORY = 8
HORIZON = 4
EMBARGO_MINUTES = HISTORY + HORIZON
SEEDS = (42, 43, 44)
FPR_BUDGET = 0.01

# Strictly network/flow/packet-derived numeric evidence.  Host resource, process,
# application-log, OSSEC/Zeek alert, login and attack-label fields are not eligible.
NETWORK_NUMERIC_NORMALIZED = {
    "scrport", "desport", "duration", "scrbytes", "desbytes", "missedbytes",
    "scrpkts", "despkts", "stripbytes", "desipbytes", "totalbytes",
    "byterate", "totalpacket", "totalpackets", "totalpkts", "packetrate",
    "paketrate", "scrpktsratio", "scrpacksratio", "despktsratio",
    "scrbytesratio", "desbytesratio", "avgrtt", "issynonly", "issynack",
    "ispureack", "iswithpayload", "finorrst", "issynwithrst", "badchecksum",
}


def norm(value):
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pick_col(columns, names):
    mapping = {norm(c): c for c in columns}
    for name in names:
        if norm(name) in mapping:
            return mapping[norm(name)]
    return None


def parse_time(df):
    date_col = pick_col(df.columns, ["Date"])
    ts_col = pick_col(df.columns, ["Timestamp", "Ts", "Time"])
    if ts_col is None:
        raise ValueError("Timestamp column required for temporal unseen-family benchmark")
    attempts = []
    if date_col and date_col != ts_col:
        attempts.append(("date+timestamp", df[date_col].astype(str).str.strip() + " " + df[ts_col].astype(str).str.strip()))
    attempts.append(("timestamp", df[ts_col]))
    for method, series in attempts:
        dt = pd.to_datetime(series.astype(str), errors="coerce", utc=True)
        if float(dt.notna().mean()) >= 0.80:
            return dt, date_col, ts_col, method
        numeric = pd.to_numeric(series, errors="coerce")
        if float(numeric.notna().mean()) >= 0.80:
            med = float(numeric.dropna().median())
            unit = "ms" if med > 1e11 else "s"
            dt = pd.to_datetime(numeric, unit=unit, errors="coerce", utc=True)
            if float(dt.notna().mean()) >= 0.80:
                return dt, date_col, ts_col, method + ":" + unit
    raise ValueError("Could not parse >=80% of timestamps")


def detect_label_hierarchy(df):
    candidates = [c for c in df.columns if "class" in norm(c) or "label" in norm(c)]
    if not candidates:
        raise ValueError("No class/label columns found")
    profiles = []
    binary_col = None
    for col in candidates:
        values = df[col].dropna().astype(str).str.strip()
        low = values.str.lower()
        uniq = sorted(set(low.unique().tolist()))
        profiles.append({"column": col, "unique": len(uniq), "sample": uniq[:25]})
        if len(uniq) <= 5 and ({"normal", "attack"} <= set(uniq) or {"benign", "attack"} <= set(uniq)):
            binary_col = col
    if binary_col is None:
        # Numeric 0/1 fallback.
        for col in candidates:
            numeric = pd.to_numeric(df[col], errors="coerce")
            uniq = set(numeric.dropna().unique().tolist())
            if uniq and uniq.issubset({0, 1, 0.0, 1.0}):
                binary_col = col
                break
    if binary_col is None:
        raise ValueError(f"No trustworthy binary label column found: {profiles}")

    family_choices = []
    for col in candidates:
        if col == binary_col:
            continue
        values = df[col].dropna().astype(str).str.strip()
        uniq = {v.lower() for v in values.unique() if v and v.lower() not in {"normal", "benign", "attack"}}
        if 2 <= len(uniq) <= 40:
            family_choices.append((len(uniq), col))
    if not family_choices:
        raise ValueError(f"No hierarchical attack-family column found: {profiles}")
    # Coarser hierarchy = fewer non-normal classes. Ties are deterministic.
    family_choices.sort(key=lambda item: (item[0], item[1]))
    family_col = family_choices[0][1]

    raw_binary = df[binary_col]
    numeric = pd.to_numeric(raw_binary, errors="coerce")
    if float(numeric.notna().mean()) >= 0.99 and set(numeric.dropna().unique()).issubset({0, 1, 0.0, 1.0}):
        y = numeric.astype("float64")
    else:
        text = raw_binary.astype(str).str.strip().str.lower()
        y = pd.Series(np.nan, index=df.index, dtype="float64")
        y.loc[text.isin(["normal", "benign"])] = 0.0
        y.loc[text.eq("attack")] = 1.0
    family = df[family_col].astype(str).str.strip()
    return y, family, binary_col, family_col, profiles


def choose_network_numeric_features(df):
    selected = []
    audit = []
    sample = df.head(min(len(df), 100000))
    for col in df.columns:
        key = norm(col)
        if key not in NETWORK_NUMERIC_NORMALIZED:
            continue
        series = sample[col].replace(["-", "?", "None", "none", "null", ""], np.nan)
        numeric = pd.to_numeric(series, errors="coerce")
        coverage = float(numeric.notna().mean())
        unique = int(numeric.nunique(dropna=True))
        accepted = coverage >= 0.50 and unique > 1
        audit.append({"column": col, "normalized": key, "numeric_coverage": coverage, "unique": unique, "accepted": accepted})
        if accepted:
            selected.append(col)
    if len(selected) < 8:
        raise ValueError(f"Strict network-only audit found only {len(selected)} usable numeric features: {selected}")
    return selected, audit


def _family_tuple(values, attack_values):
    out = sorted({str(v).strip() for v, a in zip(values, attack_values) if int(a) == 1 and str(v).strip().lower() not in {"normal", "benign", "attack", "nan", "none", ""}})
    return tuple(out)


def build_minute_state(df, dt, y, family, feature_cols):
    src_col = pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    base = pd.DataFrame({"dt": dt, "binary": y, "family": family})
    base["src"] = df[src_col].astype(str) if src_col else "GLOBAL"
    for col in feature_cols:
        base[col] = pd.to_numeric(df[col].replace(["-", "?", "None", "none", "null", ""], np.nan), errors="coerce")
    base = base.dropna(subset=["dt", "binary"]).copy()
    base["binary"] = base["binary"].astype(int)
    base["minute"] = base["dt"].dt.floor("min")
    group_keys = ["src", "minute"]
    grouped = base.groupby(group_keys, sort=True)
    state = grouped[feature_cols].agg(["mean", "std", "max"])
    state.columns = ["__".join(parts) for parts in state.columns]
    state["flow_count"] = grouped.size().astype(float)
    state["attack_now"] = grouped["binary"].max().astype(int)
    fam = grouped.apply(lambda g: _family_tuple(g["family"].tolist(), g["binary"].tolist()), include_groups=False)
    fam.name = "families"
    state = state.join(fam).reset_index().sort_values(group_keys).reset_index(drop=True)
    fcols = [c for c in state.columns if c not in {"src", "minute", "attack_now", "families"}]
    return state, fcols, src_col


def make_sequences(state, feature_cols):
    X, future, y, cutoffs, clean, hist_families, step_families = [], [], [], [], [], [], []
    for _, group in state.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        t = g["minute"].astype("int64").to_numpy() // 10**9
        attack = g["attack_now"].to_numpy(dtype=int)
        z = g[feature_cols].to_numpy(dtype=np.float32)
        fam = g["families"].tolist()
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = t[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            X.append(z[lo:i + 1])
            future.append(z[i + 1:stop])
            y.append(int(attack[i + 1:stop].max()))
            cutoffs.append(int(t[i]))
            clean.append(bool(attack[lo:i + 1].max() == 0))
            hset = set()
            for item in fam[lo:i + 1]:
                hset.update(item)
            hist_families.append(frozenset(hset))
            steps = []
            for item in fam[i + 1:stop]:
                steps.append(frozenset(item))
            step_families.append(tuple(steps))
    if not X:
        raise ValueError("No contiguous temporal sequences")
    return {
        "X": np.stack(X), "future": np.stack(future), "y": np.asarray(y, dtype=np.int8),
        "cutoff": np.asarray(cutoffs, dtype=np.int64), "clean": np.asarray(clean, dtype=bool),
        "history_families": np.asarray(hist_families, dtype=object),
        "step_families": np.asarray(step_families, dtype=object),
    }


def temporal_masks(cutoff):
    times = np.unique(cutoff)
    if len(times) < 40:
        raise ValueError("Insufficient unique temporal cutoffs")
    b1 = times[int(0.60 * (len(times) - 1))]
    b2 = times[int(0.75 * (len(times) - 1))]
    b3 = times[int(0.85 * (len(times) - 1))]
    emb = EMBARGO_MINUTES * 60
    return {
        "train": cutoff <= b1,
        "calibration": (cutoff > b1 + emb) & (cutoff <= b2),
        "policy": (cutoff > b2 + emb) & (cutoff <= b3),
        "test": cutoff > b3 + emb,
    }, {"b1": int(b1), "b2": int(b2), "b3": int(b3), "embargo_seconds": int(emb)}


def family_presence(sequences, family):
    history = np.asarray([family in s for s in sequences["history_families"]], dtype=bool)
    by_step = np.zeros((len(history), HORIZON), dtype=bool)
    for i, steps in enumerate(sequences["step_families"]):
        for h, fams in enumerate(steps):
            by_step[i, h] = family in fams
    return history, by_step


def family_split(sequences, time_masks, family):
    hist, future_steps = family_presence(sequences, family)
    future_any = future_steps.any(axis=1)
    exposed = hist | future_any
    dev_free = ~exposed
    train = time_masks["train"] & dev_free
    calibration = time_masks["calibration"] & dev_free
    policy = time_masks["policy"] & dev_free
    test_period = time_masks["test"] & ~hist
    positive = test_period & future_any
    benign_negative = time_masks["test"] & sequences["clean"] & (sequences["y"] == 0)
    evaluation = positive | benign_negative
    return {
        "train": train, "calibration": calibration, "policy": policy,
        "test_positive": positive, "test_negative": benign_negative, "test_eval": evaluation,
        "future_steps": future_steps,
    }


def fit_transform_state(train_x, train_future, arrays):
    joint = np.concatenate([train_x.reshape(-1, train_x.shape[-1]), train_future.reshape(-1, train_future.shape[-1])], axis=0).astype(np.float64)
    joint[~np.isfinite(joint)] = np.nan
    med = np.nanmedian(joint, axis=0)
    med[~np.isfinite(med)] = 0.0
    def impute(a):
        z = np.asarray(a, dtype=np.float32).copy()
        bad = ~np.isfinite(z)
        if bad.any():
            cols = np.where(bad)[-1]
            z[bad] = med[cols]
        return z
    train_imp = impute(train_x)
    future_imp = impute(train_future)
    scaler = StandardScaler().fit(np.concatenate([train_imp.reshape(-1, train_imp.shape[-1]), future_imp.reshape(-1, future_imp.shape[-1])], axis=0))
    def transform(a):
        z = impute(a)
        flat = scaler.transform(z.reshape(-1, z.shape[-1]))
        return flat.reshape(z.shape).astype(np.float32)
    return [transform(a) for a in arrays], med.tolist(), scaler


def build_world_model(features):
    import torch.nn as nn
    class World(nn.Module):
        def __init__(self, features):
            super().__init__()
            self.rnn = nn.LSTM(features, 32, batch_first=True)
            self.head = nn.Sequential(nn.Linear(32, 64), nn.ReLU(), nn.Linear(64, HORIZON * features))
        def forward(self, x):
            _, (h, _) = self.rnn(x)
            return self.head(h[-1]).reshape(len(x), HORIZON, x.shape[-1])

    return World(features)


def train_world_model(X, future, train_mask, val_mask, seed, epochs=18):
    import torch
    import torch.nn as nn
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))
    tr = np.where(train_mask)[0]
    va = np.where(val_mask)[0]
    if len(tr) < 50 or len(va) < 20:
        raise ValueError(f"State support too small train={len(tr)} validation={len(va)}")
    transformed, med, scaler = fit_transform_state(X[tr], future[tr], [X, future])
    Xs, Fs = transformed

    model = build_world_model(X.shape[-1])
    opt = torch.optim.Adam(model.parameters(), lr=0.003)
    loss_fn = nn.MSELoss()
    xtr = torch.tensor(Xs[tr]); ftr = torch.tensor(Fs[tr])
    xva = torch.tensor(Xs[va]); fva = torch.tensor(Fs[va])
    best = None; best_state = None; patience = 5; stale = 0
    batch = 256
    rng = np.random.default_rng(seed)
    for epoch in range(epochs):
        order = rng.permutation(len(tr)); model.train()
        for start in range(0, len(order), batch):
            ids = order[start:start + batch]
            pred = model(xtr[ids]); loss = loss_fn(pred, ftr[ids])
            opt.zero_grad(); loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            val = float(loss_fn(model(xva), fva).item())
        if best is None or val < best - 1e-7:
            best = val; best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}; stale = 0
        else:
            stale += 1
            if stale >= patience: break
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        pred = model(torch.tensor(Xs)).cpu().numpy()
    persistence = np.repeat(Xs[:, -1:, :], HORIZON, axis=1)
    val_model_mse = float(np.mean((pred[va] - Fs[va]) ** 2))
    val_persistence_mse = float(np.mean((persistence[va] - Fs[va]) ** 2))
    return {
        "pred": pred, "future_scaled": Fs, "persistence": persistence,
        "validation_mse": val_model_mse, "validation_persistence_mse": val_persistence_mse,
        "state_gate_passed": bool(val_model_mse < val_persistence_mse), "imputer_median": med,
        "runtime_model": model, "runtime_scaler": scaler,
    }


def robust_reference(predictions):
    flat = predictions.reshape(len(predictions), -1)
    center = np.median(flat, axis=0)
    mad = np.median(np.abs(flat - center), axis=0) * 1.4826
    std = np.std(flat, axis=0)
    scale = np.maximum(mad, np.maximum(std * 0.1, 1e-3))
    return center, scale


def anomaly_score(predictions, center, scale):
    flat = predictions.reshape(len(predictions), -1)
    return np.mean(((flat - center) / scale) ** 2, axis=1)


def fpr_threshold(benign_scores, budget=FPR_BUDGET):
    scores = np.sort(np.asarray(benign_scores, dtype=float))[::-1]
    if not len(scores):
        return None
    allowed = int(math.floor(budget * len(scores)))
    if allowed <= 0:
        return float(np.nextafter(scores[0], np.inf))
    if allowed >= len(scores):
        return float(scores[-1])
    return float(np.nextafter(scores[allowed], np.inf))


def binary_metrics(y, score, threshold):
    if threshold is None or len(y) == 0:
        return {"samples": int(len(y)), "status": "insufficient_support"}
    pred = np.asarray(score) >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "samples": int(len(y)), "positives": int((y == 1).sum()), "negatives": int((y == 0).sum()),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else None,
        "f1": float(f1_score(y, pred, zero_division=0)),
    }


def logistic_unseen_baseline(X, target, split, seed):
    tr = np.where(split["train"])[0]
    policy_benign = np.where(split["policy"] & (target == 0))[0]
    eval_idx = np.where(split["test_eval"])[0]
    if len(tr) < 50 or len(policy_benign) < 20 or len(np.unique(target[tr])) < 2:
        return {"status": "insufficient_support"}
    x = X.reshape(len(X), -1).astype(np.float64)
    x[~np.isfinite(x)] = np.nan
    med = np.nanmedian(x[tr], axis=0); med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(x); x[bad] = med[np.where(bad)[1]]
    scaler = StandardScaler().fit(x[tr]); z = scaler.transform(x)
    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed, solver="liblinear")
    model.fit(z[tr], target[tr])
    score = model.predict_proba(z)[:, 1]
    threshold = fpr_threshold(score[policy_benign])
    y_eval = split["test_positive"][eval_idx].astype(int)
    return {"threshold": threshold, "test": binary_metrics(y_eval, score[eval_idx], threshold)}


def run_family(sequences, time_masks, family, seeds, min_test_positives, min_test_negatives, epochs):
    split = family_split(sequences, time_masks, family)
    counts = {k: int(np.sum(v)) for k, v in split.items() if isinstance(v, np.ndarray) and v.dtype == bool and v.ndim == 1}
    clean_positive = split["test_positive"] & sequences["clean"]
    counts["clean_history_test_positives"] = int(clean_positive.sum())
    if counts.get("test_positive", 0) < min_test_positives or counts.get("test_negative", 0) < min_test_negatives:
        return {"status": "insufficient_test_support", "support": counts, "seeds": {}}
    rows = {}
    for seed in seeds:
        world = train_world_model(sequences["X"], sequences["future"], split["train"], split["calibration"], seed, epochs=epochs)
        cal_benign = split["calibration"] & sequences["clean"] & (sequences["y"] == 0)
        policy_benign = split["policy"] & sequences["clean"] & (sequences["y"] == 0)
        eval_idx = np.where(split["test_eval"])[0]
        if cal_benign.sum() < 20 or policy_benign.sum() < 20:
            rows[str(seed)] = {"status": "insufficient_benign_reference", "state": {k: world[k] for k in ("validation_mse", "validation_persistence_mse", "state_gate_passed")}}
            continue
        center, scale = robust_reference(world["pred"][cal_benign])
        scores = anomaly_score(world["pred"], center, scale)
        threshold = fpr_threshold(scores[policy_benign])
        y_eval = split["test_positive"][eval_idx].astype(int)
        overall = binary_metrics(y_eval, scores[eval_idx], threshold)
        clean_idx = np.where(clean_positive | split["test_negative"])[0]
        clean_y = clean_positive[clean_idx].astype(int)
        clean_metrics = binary_metrics(clean_y, scores[clean_idx], threshold)
        test_state = split["test_eval"]
        state_test_mse = float(np.mean((world["pred"][test_state] - world["future_scaled"][test_state]) ** 2))
        persistence_test_mse = float(np.mean((world["persistence"][test_state] - world["future_scaled"][test_state]) ** 2))
        horizon_rows = []
        for h in range(1, HORIZON + 1):
            c, s = robust_reference(world["pred"][cal_benign, :h])
            hscores = anomaly_score(world["pred"][:, :h], c, s)
            hth = fpr_threshold(hscores[policy_benign])
            hpos = (~np.asarray([family in fams for fams in sequences["history_families"]], dtype=bool)) & time_masks["test"] & np.asarray([any(family in steps[j] for j in range(h)) for steps in sequences["step_families"]], dtype=bool)
            hneg = time_masks["test"] & sequences["clean"] & np.asarray([all(len(steps[j]) == 0 for j in range(h)) for steps in sequences["step_families"]], dtype=bool)
            ids = np.where(hpos | hneg)[0]
            horizon_rows.append({"horizon_minutes": h, "threshold": hth, "test": binary_metrics(hpos[ids].astype(int), hscores[ids], hth)})
        baseline = logistic_unseen_baseline(sequences["X"], sequences["y"], split, seed)
        rows[str(seed)] = {
            "status": "evaluated", "state": {
                "validation_mse": world["validation_mse"], "validation_persistence_mse": world["validation_persistence_mse"],
                "state_gate_passed": world["state_gate_passed"], "test_mse": state_test_mse,
                "test_persistence_mse": persistence_test_mse,
            },
            "open_set_world_forecast": {"threshold": threshold, "test": overall, "clean_history_test": clean_metrics, "horizons": horizon_rows},
            "known_attack_logistic_baseline": baseline,
        }
    return {"status": "evaluated", "support": counts, "seeds": rows}


def summarize_family(result):
    if result.get("status") != "evaluated":
        return result.get("status")
    evaluated = [v for v in result["seeds"].values() if v.get("status") == "evaluated"]
    out = {"evaluated_seeds": len(evaluated)}
    for path, key in [
        (("open_set_world_forecast", "test", "recall"), "world_recall_mean"),
        (("open_set_world_forecast", "test", "fpr"), "world_fpr_mean"),
        (("open_set_world_forecast", "clean_history_test", "recall"), "clean_history_recall_mean"),
        (("known_attack_logistic_baseline", "test", "recall"), "logistic_recall_mean"),
        (("known_attack_logistic_baseline", "test", "fpr"), "logistic_fpr_mean"),
    ]:
        vals = []
        for row in evaluated:
            cur = row
            for part in path:
                cur = cur.get(part, {}) if isinstance(cur, dict) else {}
            if isinstance(cur, (int, float)) and cur is not None:
                vals.append(float(cur))
        out[key] = float(np.mean(vals)) if vals else None
        out[key.replace("_mean", "_sd")] = float(np.std(vals, ddof=1)) if len(vals) > 1 else None
    out["state_gate_passed_all_seeds"] = bool(evaluated and all(r["state"]["state_gate_passed"] for r in evaluated))
    out["release_gate_passed_all_seeds"] = bool(evaluated and all(
        r["state"]["state_gate_passed"] and
        r["open_set_world_forecast"]["test"].get("fpr") is not None and r["open_set_world_forecast"]["test"].get("fpr") <= FPR_BUDGET and
        r["open_set_world_forecast"]["test"].get("recall") is not None and r["open_set_world_forecast"]["test"].get("recall") >= 0.80
        for r in evaluated
    ))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=int, default=18)
    parser.add_argument("--min-test-positives", type=int, default=10)
    parser.add_argument("--min-test-negatives", type=int, default=50)
    parser.add_argument("--max-families", type=int, default=5, help="Largest supported families by test-positive count; selection is support-only, never performance-based")
    parser.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    args = parser.parse_args()
    if len(set(args.seeds)) < 3:
        parser.error("At least three distinct seeds required")
    csv_path = Path(args.csv); out = Path(args.output)
    if out.exists():
        parser.error("Output already exists; V47 evidence is immutable")
    out.mkdir(parents=True)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])
    all_families = sorted({item for steps in sequences["step_families"] for fams in steps for item in fams})
    supports = []
    for fam in all_families:
        split = family_split(sequences, time_masks, fam)
        supports.append({"family": fam, "test_positive": int(split["test_positive"].sum()), "test_negative": int(split["test_negative"].sum()), "clean_history_positive": int((split["test_positive"] & sequences["clean"]).sum())})
    eligible = [r for r in supports if r["test_positive"] >= args.min_test_positives and r["test_negative"] >= args.min_test_negatives]
    eligible.sort(key=lambda row: (-row["test_positive"], row["family"]))
    selected = [r["family"] for r in eligible[:args.max_families]]
    report = {
        "protocol": "V47 unseen-family open-set world-forecast diagnostic",
        "claim_boundary": "Held-out dataset attack families simulate unseen attacks; this is not proof of a real zero-day or verified compromise lead time.",
        "source": {"filename": csv_path.name, "bytes": int(csv_path.stat().st_size), "sha256": sha256(csv_path), "rows": int(len(df)), "columns": int(len(df.columns))},
        "history_minutes": HISTORY, "horizon_minutes": HORIZON, "seeds": list(args.seeds), "fpr_budget": FPR_BUDGET,
        "label_columns": {"binary": binary_col, "family": family_col, "profiles": label_profiles},
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "network_only_feature_audit": {"raw_selected": feature_cols, "state_feature_count": len(state_features), "audit": feature_audit, "excluded_sources": ["system resource telemetry", "process/file activity", "OSSEC/alert fields", "login fields", "attack/class labels", "IP identifiers as model features"]},
        "state_rows": int(len(state)), "sequence_rows": int(len(sequences["X"])), "source_group_column": src_col,
        "family_support": supports, "family_selection": {"method": "largest eligible families by test-positive support only; no metric-based selection", "max_families": args.max_families, "selected": selected},
        "families": {}, "automatic_containment_approved": False,
    }
    for fam in selected:
        print(f"V47 family={fam}", flush=True)
        result = run_family(sequences, time_masks, fam, tuple(args.seeds), args.min_test_positives, args.min_test_negatives, args.epochs)
        result["summary"] = summarize_family(result)
        report["families"][fam] = result
        (out / f"{norm(fam)}.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    report["all_selected_release_gates_passed"] = bool(selected and all(v.get("summary", {}).get("release_gate_passed_all_seeds") for v in report["families"].values()))
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"selected_families": selected, "summaries": {k: v["summary"] for k, v in report["families"].items()}, "all_selected_release_gates_passed": report["all_selected_release_gates_passed"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
