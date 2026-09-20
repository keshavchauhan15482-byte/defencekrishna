"""V48 frozen unseen-family alert fusion benchmark.

V47 showed two complementary facts on families that are now *development evidence*:
(1) the temporal world model often transfers state dynamics with low benign FPR, but
its single benign-manifold alert score misses too many attacks; and (2) a known-attack
logistic history model transfers strongly to several held-out families, but exceeds the
1% false-positive budget.

V48 uses the already-exposed V47 families only to choose a fixed fusion rule.  It then
freezes that rule (including an evidence hash) before evaluating support-qualified
attack families that were not part of V47 score development.  Family labels are split /
evaluation metadata only and never model inputs.

This remains a controlled public-dataset unseen-family simulation.  It is not proof of
an undisclosed production zero-day or verified pre-compromise lead time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    FPR_BUDGET,
    SEEDS,
    norm,
    sha256,
    parse_time,
    detect_label_hierarchy,
    choose_network_numeric_features,
    build_minute_state,
    make_sequences,
    temporal_masks,
    train_world_model,
    robust_reference,
    anomaly_score,
    fpr_threshold,
    binary_metrics,
)
from .v47_leave_one_family import leave_one_family_split

# These families were explicitly reported by V47 and are therefore development-only
# for V48 scorer selection.  Their V48 metrics may be inspected/tuned against.
EXPOSED_DEVELOPMENT_FAMILIES = (
    "Tampering",
    "Lateral Movement",
    "Weaponization",
    "Exfiltration",
    "Reconnaissance",
)

COMPONENTS = (
    "known_attack_transfer",
    "future_state_novelty",
    "predicted_delta_novelty",
    "transition_energy",
    "history_state_novelty",
)

POLICY_BUDGET_CANDIDATES = (0.001, 0.0025, 0.005, 0.01)


def _canonical_hash(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def tail_evidence(calibration_values, values):
    """Convert a score to benign-tail surprise without fitting attack labels.

    Larger raw values must mean more suspicious.  The returned evidence is
    -log10(empirical upper-tail p).  One pseudocount prevents infinite evidence.
    """
    cal = np.asarray(calibration_values, dtype=float)
    x = np.asarray(values, dtype=float)
    cal = cal[np.isfinite(cal)]
    if len(cal) < 2:
        raise ValueError("Need at least two benign calibration scores")
    ordered = np.sort(cal)
    idx = np.searchsorted(ordered, x, side="left")
    tail_count = len(ordered) - idx
    p = (1.0 + tail_count) / (len(ordered) + 1.0)
    return -np.log10(np.maximum(p, 1e-12))


def logistic_transfer_score(X, target, split, seed, *, return_runtime=False):
    """Known-family history scorer; held-out family is absent from split['train']."""
    tr = np.where(split["train"])[0]
    if len(tr) < 50 or len(np.unique(target[tr])) < 2:
        return None
    flat = X.reshape(len(X), -1).astype(np.float64)
    flat[~np.isfinite(flat)] = np.nan
    med = np.nanmedian(flat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(flat)
    if bad.any():
        flat[bad] = med[np.where(bad)[1]]
    scaler = StandardScaler().fit(flat[tr])
    z = scaler.transform(flat)
    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=seed,
        solver="liblinear",
    )
    model.fit(z[tr], target[tr])
    scores = model.predict_proba(z)[:, 1]
    return (scores, {"model": model, "scaler": scaler, "median": med}) if return_runtime else scores


def raw_components(world, sequences, split, seed):
    """Build inference-time scores from history plus the predicted future trajectory."""
    cal_benign = split["calibration"] & sequences["clean"] & (sequences["y"] == 0)
    policy_benign = split["policy"] & sequences["clean"] & (sequences["y"] == 0)
    if int(cal_benign.sum()) < 20 or int(policy_benign.sum()) < 20:
        return None

    pred = world["pred"]
    persistence = world["persistence"]
    last_state = persistence[:, 0, :]
    delta = pred - persistence

    # 1. Future-state novelty: where does the forecast land relative to benign forecasts?
    c_future, s_future = robust_reference(pred[cal_benign])
    future_novelty = anomaly_score(pred, c_future, s_future)

    # 2. Delta novelty: is the predicted transition vector itself unlike benign changes?
    c_delta, s_delta = robust_reference(delta[cal_benign])
    delta_novelty = anomaly_score(delta, c_delta, s_delta)

    # 3. Transition energy: magnitude of the predicted departure from persistence.
    transition_energy = np.mean(delta * delta, axis=(1, 2))

    # 4. Current-history novelty: present state may already contain transferable cues.
    c_hist, s_hist = robust_reference(last_state[cal_benign])
    history_novelty = anomaly_score(last_state[:, None, :], c_hist[None, :], s_hist[None, :])

    # 5. Known-family transfer: discriminative history score with held-out family removed.
    logistic = logistic_transfer_score(sequences["X"], sequences["y"], split, seed, return_runtime=True)
    if logistic is None:
        return None

    logistic, logistic_runtime = logistic
    raw = {
        "known_attack_transfer": logistic,
        "future_state_novelty": future_novelty,
        "predicted_delta_novelty": delta_novelty,
        "transition_energy": transition_energy,
        "history_state_novelty": history_novelty,
    }
    evidence = {}
    for name, values in raw.items():
        evidence[name] = tail_evidence(values[cal_benign], values)
    return {
        "runtime_logistic": logistic_runtime,
        "runtime_references": {"future": (c_future, s_future), "delta": (c_delta, s_delta), "history": (c_hist, s_hist)},
        "raw": raw,
        "evidence": evidence,
        "cal_benign": cal_benign,
        "policy_benign": policy_benign,
    }


def candidate_weight_sets():
    candidates = []

    def add(name, mapping):
        vec = {k: float(mapping.get(k, 0.0)) for k in COMPONENTS}
        total = sum(vec.values())
        if total <= 0:
            return
        vec = {k: v / total for k, v in vec.items()}
        key = tuple(round(vec[k], 8) for k in COMPONENTS)
        if any(tuple(round(c["weights"][k], 8) for k in COMPONENTS) == key for c in candidates):
            return
        candidates.append({"name": name, "weights": vec})

    for component in COMPONENTS:
        add(component, {component: 1.0})

    for novelty in COMPONENTS[1:]:
        add(f"transfer75_{novelty}25", {"known_attack_transfer": 0.75, novelty: 0.25})
        add(f"transfer50_{novelty}50", {"known_attack_transfer": 0.50, novelty: 0.50})
        add(f"transfer25_{novelty}75", {"known_attack_transfer": 0.25, novelty: 0.75})

    add("transfer_future_delta", {
        "known_attack_transfer": 0.50,
        "future_state_novelty": 0.25,
        "predicted_delta_novelty": 0.25,
    })
    add("transfer_delta_history", {
        "known_attack_transfer": 0.50,
        "predicted_delta_novelty": 0.25,
        "history_state_novelty": 0.25,
    })
    add("transfer_future_energy", {
        "known_attack_transfer": 0.50,
        "future_state_novelty": 0.25,
        "transition_energy": 0.25,
    })
    add("world_transition_only", {
        "future_state_novelty": 0.34,
        "predicted_delta_novelty": 0.33,
        "transition_energy": 0.33,
    })
    add("all_equal", {k: 1.0 for k in COMPONENTS})
    return candidates


def fused_score(evidence, weights):
    score = np.zeros_like(next(iter(evidence.values())), dtype=float)
    for name in COMPONENTS:
        score += float(weights.get(name, 0.0)) * evidence[name]
    return score


def _fold_metrics(cache_row, weights, policy_budget):
    score = fused_score(cache_row["components"]["evidence"], weights)
    policy = cache_row["components"]["policy_benign"]
    threshold = fpr_threshold(score[policy], policy_budget)
    ids = np.where(cache_row["split"]["test_eval"])[0]
    y = cache_row["split"]["test_positive"][ids].astype(int)
    metrics = binary_metrics(y, score[ids], threshold)
    return threshold, metrics


def choose_fusion(cache):
    """Select one fixed fusion using only already-exposed V47 development families."""
    candidates = []
    for candidate in candidate_weight_sets():
        for budget in POLICY_BUDGET_CANDIDATES:
            fold_rows = []
            for row in cache:
                threshold, metrics = _fold_metrics(row, candidate["weights"], budget)
                fold_rows.append({
                    "family": row["family"],
                    "seed": row["seed"],
                    "state_gate_passed": row["world"]["state_gate_passed"],
                    "threshold": threshold,
                    "recall": metrics.get("recall"),
                    "fpr": metrics.get("fpr"),
                })

            state_valid = [r for r in fold_rows if r["state_gate_passed"]]
            safe = [r for r in state_valid if r["fpr"] is not None and r["fpr"] <= FPR_BUDGET]
            gate = [r for r in safe if r["recall"] is not None and r["recall"] >= 0.80]
            safe_recall_sum = sum(float(r["recall"] or 0.0) for r in safe)
            mean_recall = float(np.mean([r["recall"] for r in safe])) if safe else 0.0
            max_fpr = float(max([r["fpr"] for r in state_valid], default=1.0))
            objective = (
                len(gate),
                safe_recall_sum,
                len(safe),
                mean_recall,
                -max_fpr,
                -budget,
            )
            candidates.append({
                "name": candidate["name"],
                "weights": candidate["weights"],
                "policy_budget": float(budget),
                "objective": list(objective),
                "folds": fold_rows,
            })

    candidates.sort(key=lambda row: tuple(row["objective"]), reverse=True)
    winner = candidates[0]
    return winner, candidates


def prepare_fold(sequences, time_masks, family, seed, epochs, fitting_exclusion=None):
    split = leave_one_family_split(sequences, time_masks, family)
    if fitting_exclusion is not None:
        for key in ("train", "calibration", "policy"):
            split[key] = time_masks[key] & ~fitting_exclusion
    world = train_world_model(
        sequences["X"], sequences["future"], split["train"], split["calibration"], seed, epochs=epochs
    )
    components = raw_components(world, sequences, split, seed)
    if components is None:
        return None
    return {"family": family, "seed": seed, "split": split, "world": world, "components": components}


def family_support(sequences, time_masks, family):
    split = leave_one_family_split(sequences, time_masks, family)
    return {
        "family": family,
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "positive": int(split["test_positive"].sum()),
        "negative": int(split["test_negative"].sum()),
        "clean_onset_positive": int(split["clean_onset_positive"].sum()),
    }


def evaluate_reserve_family(sequences, time_masks, family, seeds, epochs, config, *, export_dir=None, feature_names=None, fitting_exclusion=None):
    rows = {}
    for seed in seeds:
        fold = prepare_fold(sequences, time_masks, family, seed, epochs, fitting_exclusion=fitting_exclusion)
        if fold is None:
            rows[str(seed)] = {"status": "insufficient_benign_reference"}
            continue
        score = fused_score(fold["components"]["evidence"], config["weights"])
        policy = fold["components"]["policy_benign"]
        threshold = fpr_threshold(score[policy], config["policy_budget"])
        if export_dir is not None:
            from .v48_runtime import export_fold, V48Runtime
            destination = Path(export_dir) / f"{norm(family)}_seed{seed}"
            export_fold(destination, fold, config, threshold, feature_names)
            reloaded = V48Runtime(destination).predict(sequences["X"], feature_names)
            np.testing.assert_allclose(reloaded["state_scaled"], fold["world"]["pred"], atol=1e-6)
            np.testing.assert_allclose(reloaded["score"], score, atol=1e-12)
            np.testing.assert_array_equal(reloaded["alert"], (score >= threshold) & fold["world"]["state_gate_passed"])
        ids = np.where(fold["split"]["test_eval"])[0]
        y = fold["split"]["test_positive"][ids].astype(int)
        metrics = binary_metrics(y, score[ids], threshold)

        onset_ids = np.where(fold["split"]["clean_onset_positive"] | fold["split"]["test_negative"])[0]
        onset_y = fold["split"]["clean_onset_positive"][onset_ids].astype(int)
        onset = binary_metrics(onset_y, score[onset_ids], threshold)

        state_mask = fold["split"]["test_eval"]
        test_mse = float(np.mean((fold["world"]["pred"][state_mask] - fold["world"]["future_scaled"][state_mask]) ** 2))
        persistence_mse = float(np.mean((fold["world"]["persistence"][state_mask] - fold["world"]["future_scaled"][state_mask]) ** 2))

        # Standalone transfer signal under the same frozen policy budget for reference.
        transfer = fold["components"]["evidence"]["known_attack_transfer"]
        transfer_threshold = fpr_threshold(transfer[policy], config["policy_budget"])
        transfer_metrics = binary_metrics(y, transfer[ids], transfer_threshold)

        rows[str(seed)] = {
            "status": "evaluated",
            "state": {
                "validation_mse": fold["world"]["validation_mse"],
                "validation_persistence_mse": fold["world"]["validation_persistence_mse"],
                "state_gate_passed": fold["world"]["state_gate_passed"],
                "test_mse": test_mse,
                "test_persistence_mse": persistence_mse,
            },
            "fused_alert": {"threshold": threshold, "test": metrics, "clean_onset_test": onset},
            "transfer_only_reference": {"threshold": transfer_threshold, "test": transfer_metrics},
        }

    evaluated = [r for r in rows.values() if r.get("status") == "evaluated"]
    def mean_sd(path):
        vals = []
        for row in evaluated:
            cur = row
            for key in path:
                cur = cur.get(key) if isinstance(cur, dict) else None
            if isinstance(cur, (float, int)) and cur is not None:
                vals.append(float(cur))
        return {
            "mean": float(np.mean(vals)) if vals else None,
            "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else None,
        }

    summary = {
        "evaluated_seeds": len(evaluated),
        "recall": mean_sd(("fused_alert", "test", "recall")),
        "fpr": mean_sd(("fused_alert", "test", "fpr")),
        "precision": mean_sd(("fused_alert", "test", "precision")),
        "f1": mean_sd(("fused_alert", "test", "f1")),
        "state_gate_passed_all_seeds": bool(len(evaluated) == len(set(seeds)) and len(set(seeds)) >= 3 and all(r["state"]["state_gate_passed"] for r in evaluated)),
        "unseen_gate_passed_all_seeds": bool(len(evaluated) == len(set(seeds)) and len(set(seeds)) >= 3 and all(
            r["state"]["state_gate_passed"] and
            r["fused_alert"]["test"].get("fpr") is not None and r["fused_alert"]["test"]["fpr"] <= FPR_BUDGET and
            r["fused_alert"]["test"].get("recall") is not None and r["fused_alert"]["test"]["recall"] >= 0.80
            for r in evaluated
        )),
    }
    return {"seeds": rows, "summary": summary}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    p.add_argument("--min-positive", type=int, default=20)
    p.add_argument("--min-negative", type=int, default=50)
    p.add_argument("--max-reserve-families", type=int, default=4)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V48 evidence is immutable")
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    all_families = sorted({item for steps in sequences["step_families"] for fams in steps for item in fams})
    support = [family_support(sequences, time_masks, fam) for fam in all_families]

    exposed = [fam for fam in EXPOSED_DEVELOPMENT_FAMILIES if fam in all_families]
    if len(exposed) < 3:
        raise RuntimeError(f"Expected at least three exposed V47 development families, found {exposed}")

    # Development scorer selection: only families whose V47 outcomes are already public.
    dev_cache = []
    dev_support = {r["family"]: r for r in support}
    for fam in exposed:
        s = dev_support[fam]
        if s["positive"] < args.min_positive or s["negative"] < args.min_negative:
            continue
        for seed in args.seeds:
            print(f"V48 development family={fam} seed={seed}", flush=True)
            fold = prepare_fold(sequences, time_masks, fam, seed, args.epochs)
            if fold is not None:
                dev_cache.append(fold)
    if len(dev_cache) < 3:
        raise RuntimeError("Insufficient exposed-family development folds for fusion selection")

    winner, candidate_table = choose_fusion(dev_cache)
    frozen = {
        "protocol": "V48 frozen unseen-family alert fusion",
        "development_families": exposed,
        "components": list(COMPONENTS),
        "weights": winner["weights"],
        "policy_budget": winner["policy_budget"],
        "selection_objective": winner["objective"],
        "selection_candidate": winner["name"],
        "selection_rule": "lexicographic: gate folds, safe recall sum, safe folds, safe mean recall, lower max FPR, lower policy budget",
        "reserve_metrics_used_for_selection": False,
    }
    frozen["config_sha256"] = _canonical_hash(frozen)
    (out / "frozen_score_config.json").write_text(json.dumps(frozen, indent=2, allow_nan=False) + "\n")

    # Freeze reserve set by support only AFTER config is materialized; no reserve metric
    # is used to change weights, budget, feature set or component definitions.
    reserve_candidates = [
        r for r in support
        if r["family"] not in set(exposed)
        and r["positive"] >= args.min_positive
        and r["negative"] >= args.min_negative
        and r["train"] >= 50
        and r["calibration"] >= 20
        and r["policy"] >= 20
    ]
    reserve_candidates.sort(key=lambda r: (-r["positive"], r["family"]))
    reserve = [r["family"] for r in reserve_candidates[:args.max_reserve_families]]

    report = {
        "protocol": "V48 frozen unseen-family alert fusion",
        "claim_boundary": "Reserve families are unseen to V48 score selection, but remain public-dataset families. This is not proof of an undisclosed real zero-day or verified compromise lead time.",
        "source": {
            "filename": csv_path.name,
            "bytes": int(csv_path.stat().st_size),
            "sha256": sha256(csv_path),
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
        },
        "history_minutes": HISTORY,
        "horizon_minutes": HORIZON,
        "seeds": list(args.seeds),
        "release_gate": {"fpr_max": FPR_BUDGET, "recall_min": 0.80},
        "network_only_feature_audit": {"raw_selected": feature_cols, "state_feature_count": len(state_features), "audit": feature_audit},
        "label_columns": {"binary": binary_col, "family": family_col, "profiles": label_profiles},
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "state_rows": int(len(state)),
        "sequence_rows": int(len(sequences["X"])),
        "source_group_column": src_col,
        "family_support": support,
        "development": {
            "families": exposed,
            "folds": len(dev_cache),
            "winner": winner,
            "candidate_count": len(candidate_table),
        },
        "frozen_score_config": frozen,
        "reserve_selection": {
            "method": "largest support-qualified non-V47 families; no model metric used",
            "selected": reserve,
            "eligible": reserve_candidates,
        },
        "reserve_results": {},
        "automatic_containment_approved": False,
    }

    for fam in reserve:
        print(f"V48 RESERVE family={fam} config_sha256={frozen['config_sha256']}", flush=True)
        result = evaluate_reserve_family(sequences, time_masks, fam, tuple(args.seeds), args.epochs, frozen)
        report["reserve_results"][fam] = result
        (out / f"reserve_{norm(fam)}.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")

    report["all_reserve_unseen_gates_passed"] = bool(
        reserve and all(v["summary"]["unseen_gate_passed_all_seeds"] for v in report["reserve_results"].values())
    )
    report["pre_compromise_claim_supported"] = False
    report["reason_pre_compromise_unavailable"] = "Dataset family labels do not independently establish successful compromise timestamps/lead time."
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")

    compact = {
        "frozen_score_config": frozen,
        "reserve_families": reserve,
        "reserve_summaries": {k: v["summary"] for k, v in report["reserve_results"].items()},
        "all_reserve_unseen_gates_passed": report["all_reserve_unseen_gates_passed"],
    }
    print(json.dumps(compact, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
