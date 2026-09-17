"""V22: honest dual-lane unseen-family defence development gate.

Lane A remains Garuda future forecasting (V21). Lane B is a strict network-only
unknown-onset detector evaluated on the first attack-bearing 30-second window.
The held-out family is absent from train/calibration/policy blocks in both lanes.
Final frozen validation families are never scored here.
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
import v21_dev_microstructure_ood as v21

WINDOW_SECONDS = 30
HISTORY_WINDOWS = 16
OUT = Path("artifacts/v22_dev")
OUT.mkdir(parents=True, exist_ok=True)
ALPHAS = (0.0, 0.25, 0.5, 0.75, 1.0)


def epoch_seconds(series):
    origin = pd.Timestamp("1970-01-01", tz="UTC")
    return ((series - origin).dt.total_seconds().round().astype("int64")).to_numpy()


def make_onset_examples(state, fcols):
    X, target, cutoff, clean_before, hist_fams, current_fams, first_onset = [], [], [], [], [], [], []
    for _, g in state.groupby("src", sort=False):
        g = g.sort_values("bin").reset_index(drop=True)
        t = epoch_seconds(g["bin"])
        a = g["attack_now"].to_numpy(int)
        z = g[fcols].to_numpy(np.float32)
        fam = [set(x) for x in g["family_now"]]
        for i in range(HISTORY_WINDOWS, len(g)):
            lo = i - HISTORY_WINDOWS
            span = t[lo:i + 1]
            if len(span) != HISTORY_WINDOWS + 1 or not np.all(np.diff(span) == WINDOW_SECONDS):
                continue
            h = z[lo:i]
            cur = z[i]
            prev = z[i - 1]
            prev4 = h[-4:].mean(0)
            prev8 = h[-8:].mean(0)
            summary = np.concatenate([
                cur,
                cur - prev,
                cur - prev4,
                cur - prev8,
                h.mean(0),
                h.std(0),
            ]).astype(np.float32)
            prior_family_union = set().union(*fam[lo:i]) if i > lo else set()
            cf = set(fam[i])
            X.append(summary)
            target.append(int(a[i]))
            cutoff.append(int(t[i]))
            clean_before.append(bool(a[lo:i].max() == 0))
            hist_fams.append(tuple(sorted(prior_family_union)))
            current_fams.append(tuple(sorted(cf)))
            first_onset.append(tuple(sorted(cf - prior_family_union)))
    if not X:
        raise RuntimeError("No contiguous onset examples")
    return (
        np.stack(X), np.asarray(target, int), np.asarray(cutoff, np.int64),
        np.asarray(clean_before, bool), np.asarray(hist_fams, object),
        np.asarray(current_fams, object), np.asarray(first_onset, object),
    )


def contains_family(arr, family):
    return np.asarray([family in set(x) for x in arr], bool)


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
    if len(benign) < 100:
        raise RuntimeError("insufficient benign policy support")
    return float(np.quantile(benign, 1 - budget, method="higher"))


def metrics(y, p, th):
    pred = p >= th
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y)), "benign": int((y == 0).sum()), "attack": int((y == 1).sum()),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else None,
        "threshold": float(th),
    }


def split_blocks(cutoff):
    blocks = cutoff // v19.BLOCK_SECONDS
    pos = cutoff % v19.BLOCK_SECONDS
    eligible = (pos >= HISTORY_WINDOWS * WINDOW_SECONDS) & (pos <= v19.BLOCK_SECONDS - 1)
    ub = np.sort(np.unique(blocks[eligible]))
    rank = {int(b): i for i, b in enumerate(ub)}
    mod = np.asarray([rank.get(int(b), -1) % 10 for b in blocks])
    return {
        "train": np.where(eligible & np.isin(mod, [0, 1, 2, 3, 4, 5]))[0],
        "calibration": np.where(eligible & (mod == 6))[0],
        "policy": np.where(eligible & (mod == 7))[0],
        "test": np.where(eligible & np.isin(mod, [8, 9]))[0],
    }, blocks, eligible


def run_onset_family(X, target, cutoff, clean_before, hist_fams, current_fams, first_onset, family, seed):
    split, blocks, eligible = split_blocks(cutoff)
    current = contains_family(current_fams, family)
    history = contains_family(hist_fams, family)
    exposed = current | history
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
    if len(tr) > 100000:
        tr = rng.choice(tr, 100000, replace=False)

    med = np.nanmedian(X[tr].astype(np.float64), axis=0)
    med[~np.isfinite(med)] = 0.0
    Z = X.astype(np.float32, copy=True)
    bad = ~np.isfinite(Z)
    if bad.any():
        Z[bad] = med[np.where(bad)[1]].astype(np.float32)
    scaler = StandardScaler().fit(Z[tr])
    ZA = scaler.transform(Z)

    model = HistGradientBoostingClassifier(
        max_iter=350, learning_rate=.05, max_leaf_nodes=31,
        min_samples_leaf=15, l2_regularization=1.5,
        class_weight="balanced", random_state=seed,
    )
    model.fit(ZA[tr], target[tr])
    cal = calibrator(model.predict_proba(ZA[ca])[:, 1], target[ca])
    psup = apply_cal(cal, model.predict_proba(ZA)[:, 1])

    benign_tr = tr[target[tr] == 0]
    omed, oscale = v21.robust_ood_fit(ZA, benign_tr)
    oraw = v21.robust_ood_score(ZA, omed, oscale)
    pood = v21.percentile_from_ref(oraw[benign_tr], oraw)

    onset = contains_family(first_onset, family) & clean_before
    allidx = np.where(eligible)[0]
    pos_all = allidx[current[allidx]]
    pos_onset = allidx[onset[allidx]]
    negbase = split["test"]
    neg = negbase[np.asarray([(int(blocks[i]) not in held) and target[i] == 0 and clean_before[i] for i in negbase])]
    if len(pos_all) < 5 or len(pos_onset) < 1 or len(neg) < 100:
        raise RuntimeError(f"{family}: onset support all={len(pos_all)} first={len(pos_onset)} benign={len(neg)}")

    curves = {}
    for budget in v19.POLICY_FPR_BUDGETS:
        best = None
        for alpha in ALPHAS:
            ppo = alpha * psup[po] + (1.0 - alpha) * pood[po]
            th = threshold_from_policy(target[po], ppo, budget)
            pm = metrics(target[po], ppo, th)
            cand = (pm["recall"], -pm["fpr"], alpha, th)
            if best is None or cand > best:
                best = cand
        _, _, alpha, th = best
        pall = alpha * psup[pos_all] + (1.0 - alpha) * pood[pos_all]
        pon = alpha * psup[pos_onset] + (1.0 - alpha) * pood[pos_onset]
        pneg = alpha * psup[neg] + (1.0 - alpha) * pood[neg]
        yall = np.concatenate([np.ones(len(pos_all), int), np.zeros(len(neg), int)])
        yon = np.concatenate([np.ones(len(pos_onset), int), np.zeros(len(neg), int)])
        mall = metrics(yall, np.concatenate([pall, pneg]), th)
        mon = metrics(yon, np.concatenate([pon, pneg]), th)
        mall["alpha_supervised"] = float(alpha)
        mall["alpha_ood"] = float(1.0 - alpha)
        curves[str(budget)] = {"all_attack_windows": mall, "first_clean_onset_window": mon}

    return {
        "family": family,
        "seed": seed,
        "heldout_blocks": len(held),
        "heldout_family_exposure_in_train_cal_policy": 0,
        "support": {
            "heldout_attack_windows": int(len(pos_all)),
            "first_clean_onset_windows": int(len(pos_onset)),
            "clean_benign_windows": int(len(neg)),
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

    state, fcols, numeric, cats, cols = v21.build_state(df, dt, y, family_col, binary_col, date_col, ts_col)
    X, target, cutoff, clean_before, hist_fams, current_fams, first_onset = make_onset_examples(state, fcols)

    report = {
        "schema": "krishna-v22-dual-lane-dev-v1",
        "purpose": "Development only. Garuda future forecasting and Krishna unknown-onset detection are separate claims; frozen final families are not scored.",
        "window_seconds": WINDOW_SECONDS,
        "history_minutes_for_onset_context": 8,
        "development_families": v19.DEV_FAMILIES,
        "final_validation_families_not_scored": v19.FINAL_FAMILIES,
        "network_numeric": numeric,
        "network_categorical": cats,
        "columns": cols,
        "onset_feature_count": int(X.shape[1]),
        "results": {},
    }

    completed = []
    for fam in v19.DEV_FAMILIES:
        report["results"][fam] = {}
        try:
            for seed in base.SEEDS:
                print(f"V22 onset family={fam} seed={seed}", flush=True)
                r = run_onset_family(X, target, cutoff, clean_before, hist_fams, current_fams, first_onset, fam, seed)
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
        per_family = {}
        for fam in completed:
            allm = {k: float(np.mean([report["results"][fam][str(s)]["budget_curve"][key]["all_attack_windows"][k] for s in base.SEEDS])) for k in ["fpr", "recall", "precision", "f1"]}
            onsetm = {k: float(np.mean([report["results"][fam][str(s)]["budget_curve"][key]["first_clean_onset_window"][k] for s in base.SEEDS])) for k in ["fpr", "recall", "precision", "f1"]}
            per_family[fam] = {"all_attack_windows": allm, "first_clean_onset_window": onsetm}
        budgets[key] = {
            "macro_all_attack": {k: float(np.mean([x["all_attack_windows"][k] for x in per_family.values()])) for k in ["fpr", "recall", "precision", "f1"]},
            "macro_first_clean_onset": {k: float(np.mean([x["first_clean_onset_window"][k] for x in per_family.values()])) for k in ["fpr", "recall", "precision", "f1"]},
            "per_family": per_family,
        }

    feasible = [(b, v) for b, v in budgets.items() if v["macro_first_clean_onset"]["fpr"] <= 0.02]
    chosen = max(feasible, key=lambda x: x[1]["macro_first_clean_onset"]["recall"]) if feasible else min(budgets.items(), key=lambda x: x[1]["macro_first_clean_onset"]["fpr"])
    report["budget_results"] = budgets
    report["chosen_policy_budget"] = chosen[0]
    report["macro_first_clean_onset"] = chosen[1]["macro_first_clean_onset"]
    report["macro_all_attack"] = chosen[1]["macro_all_attack"]
    report["development_target"] = {
        "target_macro_fpr": 0.02,
        "target_macro_first_clean_onset_recall": 0.80,
        "macro_fpr_pass": chosen[1]["macro_first_clean_onset"]["fpr"] <= 0.02,
        "macro_onset_recall_pass": chosen[1]["macro_first_clean_onset"]["recall"] >= 0.80,
        "all_family_onset_recall_ge_0_80": all(x["first_clean_onset_window"]["recall"] >= 0.80 for x in chosen[1]["per_family"].values()),
        "ready_for_frozen_final_onset_validation": bool(
            chosen[1]["macro_first_clean_onset"]["fpr"] <= 0.02
            and chosen[1]["macro_first_clean_onset"]["recall"] >= 0.80
            and all(x["first_clean_onset_window"]["recall"] >= 0.80 for x in chosen[1]["per_family"].values())
        ),
    }

    (OUT / "results.json").write_text(json.dumps(report, indent=2))
    (OUT / "REPORT.md").write_text(
        "# V22 dual-lane development\n\n"
        "Garuda future forecasting remains a separate claim. This report evaluates the strict network-only unknown-onset fallback on the first attack-bearing 30-second window.\n\n"
        "```json\n" + json.dumps({
            "chosen_policy_budget": report["chosen_policy_budget"],
            "macro_first_clean_onset": report["macro_first_clean_onset"],
            "macro_all_attack": report["macro_all_attack"],
            "development_target": report["development_target"],
        }, indent=2) + "\n```\n"
    )
    print("V22_FINAL", json.dumps({"onset": report["macro_first_clean_onset"], "gate": report["development_target"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
