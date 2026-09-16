"""State-first V46 trainer for the additive SIH PS-complete feature schema.

The trainer preserves the V45 evidence discipline while accepting the expanded
packet/flow feature vector.  It can run state-only on unlabeled PCAP telemetry,
or train risk/stage heads when explicit labels exist.  Development-reused
holdouts are labelled as such and can never be promoted by this module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

from .annotations import MITRE, STAGES
from .calibration import apply as apply_calibration
from .calibration import family_report, fit as fit_calibration, future_target, select_policy
from .data import campaign_examples
from .model import GraphWorldModel
from .ps_complete import FEATURES, SCHEMA, load_dataset
from .train import batch, metrics, pooled, stage_batch
from .train_v45_core import fit_risk_head, fit_stage_head, fit_state, infer, _horizon_report


def _save_model(model: GraphWorldModel, path: Path, metadata: dict) -> None:
    """Save a schema-correct V46 research checkpoint without changing legacy loader semantics."""
    np.savez_compressed(
        path,
        **{name: tensor.data for name, tensor in model.params.items()},
        metadata=json.dumps(metadata, sort_keys=True),
        config=json.dumps(model.config, sort_keys=True),
        schema=SCHEMA,
    )


def _validate_contract(datasets: list[dict]) -> None:
    if not datasets:
        raise ValueError("At least one V46 dataset is required")
    keys = {(d["metadata"].get("schema"), tuple(d["metadata"].get("features", [])), d["metadata"].get("mode"),
             d["metadata"].get("window_seconds"), d["metadata"].get("max_nodes")) for d in datasets}
    if len(keys) != 1:
        raise ValueError("All V46 campaigns must share one exact graph/feature contract")
    schema, features, _, window_seconds, _ = next(iter(keys))
    if schema != SCHEMA or list(features) != FEATURES or int(window_seconds) != 10:
        raise ValueError("V46 requires the frozen 10-second PS-complete schema")
    campaigns = [d["metadata"].get("campaign_id") for d in datasets]
    hashes = [d["metadata"].get("source_sha256") for d in datasets]
    if any(not isinstance(x, str) or not x for x in campaigns + hashes):
        raise ValueError("Explicit campaign_id and source_sha256 required")
    if len(set(campaigns)) != len(campaigns) or len(set(hashes)) != len(hashes):
        raise ValueError("Campaign IDs and source hashes must be unique")
    if any(not np.isin(d["y"], [-1, 0, 1]).all() for d in datasets):
        raise ValueError("Unknown labels must remain -1; labels are limited to -1/0/1")


def _validate_manifest(datasets: list[dict], manifest: dict) -> None:
    expected = {d["metadata"]["campaign_id"] for d in datasets}
    assigned = []
    for split in ("train", "validation", "test"):
        values = manifest.get(split)
        if not isinstance(values, list) or not values:
            raise ValueError(f"Explicit non-empty {split} campaign list required")
        assigned.extend(values)
    if len(assigned) != len(set(assigned)) or set(assigned) != expected:
        raise ValueError("Campaign split must be disjoint and exhaustive")


def _clean_history_metrics(labels, probabilities, history_flags, threshold):
    clean = history_flags == 0
    target = future_target(labels[clean])
    known = target >= 0
    if not known.any():
        return {"samples": 0, "positives": 0, "status": "no_known_clean_history_targets"}
    score = probabilities[clean].max(axis=1)[known]
    return metrics(target[known], score, threshold if threshold is not None else 1.000001)


def _train_logistic(train, valid, test, seed: int, fpr_budget: float):
    train_target = future_target(train[4])
    valid_target = future_target(valid[4])
    test_target = future_target(test[4])
    known_train = train_target >= 0
    if len(np.unique(train_target[known_train])) < 2:
        return None, {"status": "insufficient_training_classes"}
    flat = [pooled(a[0], a[2]).reshape(len(a[0]), -1) for a in (train, valid, test)]
    model = LogisticRegression(max_iter=2000, random_state=seed).fit(flat[0][known_train], train_target[known_train])
    valid_probability = model.predict_proba(flat[1])[:, 1]
    test_probability = model.predict_proba(flat[2])[:, 1]
    vk = valid_target >= 0
    tk = test_target >= 0
    policy = select_policy(valid_target[vk], valid_probability[vk], fpr_budget) if vk.any() else {"threshold": None, "status": "no_known_validation_targets"}
    threshold = policy.get("threshold")
    result = {
        "validation_alert_selection": policy,
        "test": metrics(test_target[tk], test_probability[tk], threshold if threshold is not None else 1.000001),
        "temporal_dynamics": False,
        "equal_observed_history": True,
    }
    return model, result


def run(args):
    datasets = [load_dataset(path) for path in args.graphs]
    _validate_contract(datasets)
    manifest = json.loads(Path(args.split_manifest).read_text())
    _validate_manifest(datasets, manifest)
    splits, boundaries = campaign_examples(datasets, manifest, args.history, args.horizon, args.stride, allow_unknown=True)
    arrays = [batch(datasets, split, args.history, args.horizon) for split in splits]
    train, valid, test = arrays

    out = Path(args.output)
    if out.exists() and any(out.iterdir()):
        raise ValueError("Output must be empty; evidence artifacts are immutable")
    out.mkdir(parents=True, exist_ok=True)

    weak = any(d["metadata"].get("release_evidence_eligible") is False for d in datasets)
    scope = args.evaluation_scope
    if scope == "new_predeclared_holdout" and weak:
        raise ValueError("Weak/development labels cannot be declared a new release-grade holdout")

    report = {
        "schema": SCHEMA,
        "features": FEATURES,
        "feature_count": len(FEATURES),
        "protocol": "V46 PS-complete state-first forecasting",
        "evaluation_scope": scope,
        "release_evidence_eligible": bool(scope == "new_predeclared_holdout" and not weak),
        "config": vars(args),
        "split_boundaries": boundaries,
        "split_counts": [len(a[0]) for a in arrays],
        "sources": [{k: v for k, v in d["metadata"].items() if k != "node_names"} for d in datasets],
        "target": "future malicious-traffic evidence over 10/20/30/40 seconds; not verified compromise probability",
        "selection": "state checkpoint by validation MSE with epoch-0 persistence; risk/stage heads fitted only after state acceptance",
        "automatic_containment_approved": False,
        "models": {},
        "claims_boundary": [
            "forecast horizon is not compromise lead time",
            "schedule-assisted IDS2018 labels are development-only",
            "MITRE stages require explicit reviewed stage_y supervision",
            "test labels are never used for fitting/calibration/threshold selection",
        ],
    }

    if not args.state_only:
        lr, lr_result = _train_logistic(train, valid, test, args.seed, args.fpr_budget)
        report["models"]["logistic_regression"] = lr_result
        if lr is not None:
            np.savez_compressed(out / "logistic_regression.npz", weights=lr.coef_, bias=lr.intercept_)

    stage_arrays = [None, None, None]
    if args.stage_supervision:
        if any("stage_y" not in d or d["stage_y"].shape != (len(d["y"]), len(STAGES)) for d in datasets):
            raise ValueError("Every campaign needs explicit five-stage stage_y supervision")
        stage_arrays = [stage_batch(datasets, split, args.history, args.horizon) for split in splits]
        if not (stage_arrays[0] == 1).any():
            raise ValueError("Positive stage supervision is required in training")

    train_target = future_target(train[4])
    risk_classes_ok = len(np.unique(train_target[train_target >= 0])) >= 2
    if not args.state_only and not risk_classes_ok:
        raise ValueError("Risk training needs both known benign and malicious future targets")

    for architecture in ("lstm", "gnn_lstm"):
        started = time.monotonic()
        model = GraphWorldModel(
            architecture=architecture,
            feature_dim=len(FEATURES),
            seed=args.seed,
            decoder="residual",
            stage_count=len(STAGES) if args.stage_supervision else 0,
        )
        state_fit = fit_state(model, train, valid, epochs=args.state_epochs, patience=args.patience, seed=args.seed)
        state_pass = bool(state_fit["persistence_gate"]["passed"])
        mean_test, raw_test_risk, _ = infer(model, test, args.horizon)
        persistence_test = pooled(test[0], test[2])[:, -1:]
        result = {
            "state_training": state_fit,
            "state_gate_passed": state_pass,
            "state_mse": float(np.mean((mean_test - test[3]) ** 2)),
            "state_persistence_mse": float(np.mean((persistence_test - test[3]) ** 2)),
            "risk_head_trained": False,
            "calibration": {"status": "state_only" if args.state_only else "disabled_state_gate_failed"},
            "validation_alert_selection": {"threshold": None, "status": "state_only" if args.state_only else "state_gate_failed"},
            "per_family_alert_metrics": {},
            "horizon_metrics": [],
            "supervised_stages": [],
            "verified_compromise_lead_time_seconds": None,
            "automatic_containment_approved": False,
        }

        if state_pass and not args.state_only:
            result["risk_training"] = fit_risk_head(model, train, valid, epochs=args.risk_epochs, patience=args.patience, seed=args.seed)
            _, valid_risk, _ = infer(model, valid, args.horizon)
            mean_test, raw_test_risk, _ = infer(model, test, args.horizon)
            pair_known = valid[4] >= 0
            calibration = fit_calibration(valid[4][pair_known], valid_risk[pair_known])
            valid_risk = apply_calibration(valid_risk, calibration)
            test_risk = apply_calibration(raw_test_risk, calibration)
            valid_target = future_target(valid[4]); test_target = future_target(test[4])
            vk = valid_target >= 0; tk = test_target >= 0
            policy = select_policy(valid_target[vk], valid_risk.max(axis=1)[vk], args.fpr_budget) if vk.any() else {"threshold": None, "status": "no_known_validation_targets"}
            threshold = policy.get("threshold")
            result.update({
                "risk_head_trained": True,
                "calibration": calibration,
                "validation_alert_selection": policy,
                "test": metrics(test_target[tk], test_risk.max(axis=1)[tk], threshold if threshold is not None else 1.000001),
                "per_family_alert_metrics": family_report(datasets, splits[2], test[4], test_risk, threshold),
                "clean_history_warning_policy": _clean_history_metrics(test[4], test_risk, test[5], threshold),
                "horizon_metrics": _horizon_report((valid[4], test[4]), valid_risk, test_risk, args.fpr_budget, 10),
            })

            if args.stage_supervision:
                result["stage_training"] = fit_stage_head(
                    model, train, valid, stage_arrays[0], stage_arrays[1],
                    epochs=args.stage_epochs, patience=args.patience, seed=args.seed,
                )
                _, _, valid_stage = infer(model, valid, args.horizon, return_stages=True)
                _, _, test_stage = infer(model, test, args.horizon, return_stages=True)
                rows = []
                for j, stage in enumerate(STAGES):
                    vknown = stage_arrays[1][:, :, j] >= 0
                    tknown = stage_arrays[2][:, :, j] >= 0
                    if vknown.any() and len(np.unique(stage_arrays[1][:, :, j][vknown])) == 2:
                        stage_policy = select_policy(stage_arrays[1][:, :, j][vknown].astype(int), valid_stage[:, :, j][vknown], args.fpr_budget)
                    else:
                        stage_policy = {"threshold": None, "status": "insufficient_stage_validation_support"}
                    st = stage_policy.get("threshold")
                    rows.append({
                        "stage": stage, "mitre": MITRE[j], "validation_policy": stage_policy,
                        "test": metrics(stage_arrays[2][:, :, j][tknown], test_stage[:, :, j][tknown], st if st is not None else 1.000001),
                    })
                result["supervised_stages"] = rows

            np.savez_compressed(
                out / f"{architecture}_test_predictions.npz",
                probabilities=test_risk, raw_probabilities=raw_test_risk, labels=test[4],
                state_prediction=mean_test, state_target=test[3], example_indices=np.asarray(splits[2]),
                history_clean=(test[5] == 0),
            )

        metadata = {
            "schema": SCHEMA, "features": FEATURES, "architecture": architecture,
            "history": args.history, "horizon": args.horizon, "window_seconds": 10,
            "mode": datasets[0]["metadata"]["mode"], "max_nodes": datasets[0]["metadata"]["max_nodes"],
            "source_hashes": [d["metadata"]["source_sha256"] for d in datasets],
            "training_campaigns": manifest["train"], "validation_campaigns": manifest["validation"], "test_campaigns": manifest["test"],
            "evaluation_scope": scope, "release_evidence_eligible": report["release_evidence_eligible"],
            "state_head_trained": True, "risk_head_trained": bool(result["risk_head_trained"]),
            "stage_supervised": bool(args.stage_supervision and result["risk_head_trained"]),
            "automatic_containment_approved": False,
        }
        _save_model(model, out / f"{architecture}.npz", metadata)
        result["training_seconds"] = round(time.monotonic() - started, 2)
        report["models"][architecture] = result

    report["checkpoint_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob("*.npz")}
    (out / "metrics.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--history", type=int, default=8)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--stride", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--state-epochs", type=int, default=30)
    parser.add_argument("--risk-epochs", type=int, default=20)
    parser.add_argument("--stage-epochs", type=int, default=20)
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--fpr-budget", type=float, default=0.01)
    parser.add_argument("--stage-supervision", action="store_true")
    parser.add_argument("--state-only", action="store_true", help="Train state dynamics on unlabeled PCAP without inventing risk truth")
    parser.add_argument("--evaluation-scope", choices=["development_reused_holdout", "new_predeclared_holdout"], default="development_reused_holdout")
    args = parser.parse_args()
    if (args.history, args.horizon) != (8, 4):
        parser.error("V46 contract is frozen at 8 observed + 4 future windows")
    if not 0 < args.fpr_budget <= 0.01:
        parser.error("FPR budget cannot exceed 1%")
    if min(args.state_epochs, args.risk_epochs, args.stage_epochs, args.patience, args.stride) < 1:
        parser.error("Epoch/patience/stride values must be positive")
    run(args)


if __name__ == "__main__":
    main()
