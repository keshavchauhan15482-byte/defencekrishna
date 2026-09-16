"""V45 state-first forecasting trainer.

Protocol:
1. train the world model on future state MSE only;
2. select state checkpoint by validation MSE, with epoch-0 persistence included;
3. reject risk promotion unless validation state MSE beats persistence;
4. freeze the world model and train only the risk head on training labels;
5. calibrate and select alert thresholds on validation only;
6. evaluate the untouched test campaigns once, including cumulative 10/20/30/40s targets;
7. optionally train only the separate stage head when explicit stage supervision exists.

No test label is used for fitting, calibration, threshold selection or checkpoint
selection. Unknown labels remain unknown. Automatic containment is never approved
by this trainer.
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
from .autograd import Adam
from .calibration import apply as apply_calibration
from .calibration import family_report, fit as fit_calibration, future_target, select_policy
from .data import FEATURES, SCHEMA, campaign_examples, load_dataset
from .forecast_hardening import multi_horizon_targets, persistence_gate
from .model import GraphWorldModel
from .train import batch, metrics, pooled, stage_batch


def state_objective(model, arrays):
    x, adj, mask, target, *_ = arrays
    mean, _, _ = model.forward(x, adj, mask, target.shape[1])
    return (mean - target).power(2).mean()


def risk_objective(model, arrays):
    x, adj, mask, _, labels, *_ = arrays
    _, _, risk = model.forward(x, adj, mask, labels.shape[1])
    risk = .000001 + .999998 * risk
    known = (labels >= 0).astype(np.float32)
    target = np.maximum(labels, 0)
    return -((target * risk.log() + (1 - target) * (1 - risk).log()) * known).sum() / max(float(known.sum()), 1)


def stage_objective(model, arrays, stage_labels):
    x, adj, mask, _, labels, *_ = arrays
    *_, stages = model.forward(x, adj, mask, labels.shape[1], return_stages=True)
    if stages is None:
        raise ValueError("Stage objective requires a stage head")
    known = (stage_labels >= 0).astype(np.float32)
    target = np.maximum(stage_labels, 0)
    prob = .000001 + .999998 * stages
    return -((target * prob.log() + (1 - target) * (1 - prob).log()) * known).sum() / max(float(known.sum()), 1)


def _copy_weights(model):
    return {name: tensor.data.copy() for name, tensor in model.params.items()}


def _restore(model, weights):
    for name, value in weights.items():
        model.params[name].data = value.copy()


def _state_mse(model, arrays, horizon):
    x, adj, mask, target, *_ = arrays
    means = []
    for start in range(0, len(x), 64):
        mean, _, _ = model.forward(x[start:start + 64], adj[start:start + 64], mask[start:start + 64], horizon)
        means.append(mean.data)
    prediction = np.concatenate(means)
    return float(np.mean((prediction - target) ** 2)), prediction


def fit_state(model, train, valid, *, epochs, patience, seed, learning_rate=.003):
    optimizer = Adam(model.parameters(), lr=learning_rate)
    rng = np.random.default_rng(seed)
    persistence_mse = float(np.mean((pooled(valid[0], valid[2])[:, -1:] - valid[3]) ** 2))
    best_mse, _ = _state_mse(model, valid, valid[3].shape[1])
    best_epoch = 0
    best_weights = _copy_weights(model)
    curve = [{"epoch": 0, "validation_state_mse": best_mse, "persistence_mse": persistence_mse}]
    last_epoch = 0
    for epoch in range(1, epochs + 1):
        last_epoch = epoch
        order = rng.permutation(len(train[0]))
        values = []
        for start in range(0, len(order), 32):
            ids = order[start:start + 32]
            arrays = tuple(a[ids] for a in train)
            objective = state_objective(model, arrays)
            objective.backward()
            optimizer.step()
            values.append(float(objective.data))
        val_mse, _ = _state_mse(model, valid, valid[3].shape[1])
        curve.append({
            "epoch": epoch,
            "train_state_mse": float(np.mean(values)),
            "validation_state_mse": val_mse,
            "persistence_mse": persistence_mse,
        })
        if val_mse < best_mse:
            best_mse = val_mse
            best_epoch = epoch
            best_weights = _copy_weights(model)
        if epoch - best_epoch >= patience:
            break
    _restore(model, best_weights)
    gate = persistence_gate(best_mse, persistence_mse)
    return {
        "best_epoch": best_epoch,
        "epochs_run": last_epoch,
        "validation_state_mse": best_mse,
        "validation_persistence_mse": persistence_mse,
        "persistence_gate": gate,
        "curve": curve,
    }


def _risk_bce(model, arrays):
    return float(risk_objective(model, arrays).data)


def fit_risk_head(model, train, valid, *, epochs, patience, seed, learning_rate=.003):
    params = [model.params["risk"], model.params["risk_b"]]
    optimizer = Adam(params, lr=learning_rate)
    rng = np.random.default_rng(seed + 1000)
    best = _risk_bce(model, valid)
    best_epoch = 0
    best_weights = {"risk": model.params["risk"].data.copy(), "risk_b": model.params["risk_b"].data.copy()}
    curve = [{"epoch": 0, "validation_risk_bce": best}]
    last_epoch = 0
    for epoch in range(1, epochs + 1):
        last_epoch = epoch
        order = rng.permutation(len(train[0]))
        values = []
        for start in range(0, len(order), 32):
            ids = order[start:start + 32]
            arrays = tuple(a[ids] for a in train)
            objective = risk_objective(model, arrays)
            objective.backward()
            optimizer.step()
            values.append(float(objective.data))
        value = _risk_bce(model, valid)
        curve.append({"epoch": epoch, "train_risk_bce": float(np.mean(values)), "validation_risk_bce": value})
        if value < best:
            best = value
            best_epoch = epoch
            best_weights = {"risk": model.params["risk"].data.copy(), "risk_b": model.params["risk_b"].data.copy()}
        if epoch - best_epoch >= patience:
            break
    model.params["risk"].data = best_weights["risk"]
    model.params["risk_b"].data = best_weights["risk_b"]
    return {"best_epoch": best_epoch, "epochs_run": last_epoch, "validation_risk_bce": best, "curve": curve}


def fit_stage_head(model, train, valid, train_stage, valid_stage, *, epochs, patience, seed, learning_rate=.003):
    params = [model.params["stage"], model.params["stage_b"]]
    optimizer = Adam(params, lr=learning_rate)
    rng = np.random.default_rng(seed + 2000)

    def score():
        return float(stage_objective(model, valid, valid_stage).data)

    best = score()
    best_epoch = 0
    best_weights = {"stage": model.params["stage"].data.copy(), "stage_b": model.params["stage_b"].data.copy()}
    curve = [{"epoch": 0, "validation_stage_bce": best}]
    last_epoch = 0
    for epoch in range(1, epochs + 1):
        last_epoch = epoch
        order = rng.permutation(len(train[0]))
        vals = []
        for start in range(0, len(order), 32):
            ids = order[start:start + 32]
            arrays = tuple(a[ids] for a in train)
            objective = stage_objective(model, arrays, train_stage[ids])
            objective.backward()
            optimizer.step()
            vals.append(float(objective.data))
        value = score()
        curve.append({"epoch": epoch, "train_stage_bce": float(np.mean(vals)), "validation_stage_bce": value})
        if value < best:
            best = value
            best_epoch = epoch
            best_weights = {"stage": model.params["stage"].data.copy(), "stage_b": model.params["stage_b"].data.copy()}
        if epoch - best_epoch >= patience:
            break
    model.params["stage"].data = best_weights["stage"]
    model.params["stage_b"].data = best_weights["stage_b"]
    return {"best_epoch": best_epoch, "epochs_run": last_epoch, "validation_stage_bce": best, "curve": curve}


def infer(model, arrays, horizon, return_stages=False):
    x, adj, mask, *_ = arrays
    means, risks, stages = [], [], []
    for start in range(0, len(x), 64):
        result = model.forward(x[start:start + 64], adj[start:start + 64], mask[start:start + 64], horizon, return_stages=return_stages)
        means.append(result[0].data)
        risks.append(result[2].data)
        if return_stages:
            stages.append(result[3].data)
    return np.concatenate(means), np.concatenate(risks), (np.concatenate(stages) if stages else None)


def _horizon_report(labels, valid_prob, test_prob, fpr_budget, window_seconds):
    targets_v = multi_horizon_targets(labels[0])
    targets_t = multi_horizon_targets(labels[1])
    rows = []
    for h in range(targets_v.shape[1]):
        vy = targets_v[:, h]
        ty = targets_t[:, h]
        vp = np.max(valid_prob[:, : h + 1], axis=1)
        tp = np.max(test_prob[:, : h + 1], axis=1)
        vk = vy >= 0
        tk = ty >= 0
        policy = select_policy(vy[vk], vp[vk], fpr_budget) if vk.any() else {"threshold": None, "status": "no_known_validation_targets"}
        threshold = policy.get("threshold")
        rows.append({
            "horizon_seconds": int((h + 1) * window_seconds),
            "validation_policy": policy,
            "test": metrics(ty[tk], tp[tk], threshold if threshold is not None else 1.000001),
        })
    return rows


def run(args):
    datasets = [load_dataset(path) for path in args.graphs]
    manifest = json.loads(Path(args.split_manifest).read_text())
    splits, boundaries = campaign_examples(
        datasets, manifest, args.history, args.horizon, args.stride, allow_unknown=True
    )
    arrays = [batch(datasets, split, args.history, args.horizon) for split in splits]
    train, valid, test = arrays
    train_target = future_target(train[4])
    if len(np.unique(train_target[train_target >= 0])) < 2:
        raise ValueError("Training future-risk target needs both classes")

    stage_arrays = [None, None, None]
    if args.stage_supervision:
        if any("stage_y" not in d for d in datasets):
            raise ValueError("Explicit stage_y required for every campaign")
        stage_arrays = [stage_batch(datasets, split, args.history, args.horizon) for split in splits]
        if not (stage_arrays[0] == 1).any():
            raise ValueError("Positive verified stage supervision required")

    out = Path(args.output)
    if out.exists() and any(out.iterdir()):
        raise ValueError("Output must be empty; V45 evidence is immutable")
    out.mkdir(parents=True, exist_ok=True)

    report = {
        "schema": SCHEMA,
        "protocol": "V45 state-first forecasting",
        "evaluation_scope": "new_predeclared_holdout",
        "config": vars(args),
        "split_boundaries": boundaries,
        "split_counts": [len(x[0]) for x in arrays],
        "selection": "state checkpoint by validation MSE including epoch-0 persistence; risk/stage heads fitted separately after state acceptance",
        "target": "network-only future malicious-flow evidence; cumulative 10/20/30/40 second targets; not compromise probability",
        "models": {},
        "automatic_containment_approved": False,
    }

    # Equal-evidence logistic baseline: identical observed history, future any-horizon target.
    flat = [pooled(a[0], a[2]).reshape(len(a[0]), -1) for a in arrays]
    train_known = train_target >= 0
    lr = LogisticRegression(max_iter=2000, random_state=args.seed).fit(flat[0][train_known], train_target[train_known])
    vp_lr = lr.predict_proba(flat[1])[:, 1]
    tp_lr = lr.predict_proba(flat[2])[:, 1]
    val_target = future_target(valid[4])
    test_target = future_target(test[4])
    vk = val_target >= 0
    tk = test_target >= 0
    lr_policy = select_policy(val_target[vk], vp_lr[vk], args.fpr_budget)
    lr_threshold = lr_policy.get("threshold")
    report["models"]["logistic_regression"] = {
        "validation_alert_selection": lr_policy,
        "test": metrics(test_target[tk], tp_lr[tk], lr_threshold if lr_threshold is not None else 1.000001),
    }
    np.savez_compressed(out / "logistic_regression.npz", weights=lr.coef_, bias=lr.intercept_, threshold=lr_threshold if lr_threshold is not None else np.nan)

    for architecture in ("lstm", "gnn_lstm"):
        started = time.monotonic()
        model = GraphWorldModel(
            architecture=architecture,
            seed=args.seed,
            decoder="residual",
            stage_count=len(STAGES) if args.stage_supervision else 0,
        )
        state_fit = fit_state(
            model, train, valid, epochs=args.state_epochs, patience=args.patience, seed=args.seed
        )
        state_pass = state_fit["persistence_gate"]["passed"]
        result = {
            "state_training": state_fit,
            "validation_state_mse": state_fit["validation_state_mse"],
            "validation_persistence_mse": state_fit["validation_persistence_mse"],
            "calibration": {"status": "disabled_state_gate_failed"},
            "validation_alert_selection": {"threshold": None, "status": "state_gate_failed"},
            "per_family_alert_metrics": {},
            "clean_history_warning_policy": {"test": {"samples": 0, "positives": 0, "status": "state_gate_failed"}},
            "horizon_metrics": [],
            "measured_compromise_lead_time_seconds": None,
            "risk_head_trained": False,
            "state_gate_passed": bool(state_pass),
            "automatic_containment_approved": False,
        }

        mean_test, raw_test_risk, _ = infer(model, test, args.horizon)
        base_test = pooled(test[0], test[2])[:, -1:]
        result["state_mse"] = float(np.mean((mean_test - test[3]) ** 2))
        result["state_persistence_mse"] = float(np.mean((base_test - test[3]) ** 2))

        if state_pass:
            risk_fit = fit_risk_head(
                model, train, valid, epochs=args.risk_epochs, patience=args.patience, seed=args.seed
            )
            _, valid_risk, _ = infer(model, valid, args.horizon)
            mean_test, raw_test_risk, _ = infer(model, test, args.horizon)
            known_pairs = valid[4] >= 0
            calibration = fit_calibration(valid[4][known_pairs], valid_risk[known_pairs])
            valid_risk = apply_calibration(valid_risk, calibration)
            test_risk = apply_calibration(raw_test_risk, calibration)

            val_target = future_target(valid[4])
            test_target = future_target(test[4])
            vk = val_target >= 0
            tk = test_target >= 0
            policy = select_policy(val_target[vk], valid_risk.max(axis=1)[vk], args.fpr_budget)
            alert_threshold = policy.get("threshold")
            threshold_for_metrics = alert_threshold if alert_threshold is not None else 1.000001
            clean_valid = valid[5] == 0
            clean_test = test[5] == 0
            cv_target = future_target(valid[4][clean_valid])
            cv_known = cv_target >= 0
            early_policy = select_policy(
                cv_target[cv_known], valid_risk[clean_valid].max(axis=1)[cv_known], args.fpr_budget
            ) if cv_known.any() else {"threshold": None, "status": "no_known_clean_validation_targets"}
            early_threshold = early_policy.get("threshold")
            clean_test_target = future_target(test[4][clean_test])
            clean_known = clean_test_target >= 0

            result.update({
                "risk_head_trained": True,
                "risk_training": risk_fit,
                "calibration": calibration,
                "validation_alert_selection": policy,
                "test": metrics(test_target[tk], test_risk.max(axis=1)[tk], threshold_for_metrics),
                "per_family_alert_metrics": family_report(datasets, splits[2], test[4], test_risk, alert_threshold),
                "clean_history_warning_policy": {
                    "validation_selection": early_policy,
                    "test": metrics(
                        clean_test_target[clean_known],
                        test_risk[clean_test].max(axis=1)[clean_known],
                        early_threshold if early_threshold is not None else 1.000001,
                    ),
                },
                "horizon_metrics": _horizon_report(
                    (valid[4], test[4]), valid_risk, test_risk, args.fpr_budget, datasets[0]["metadata"]["window_seconds"]
                ),
            })

            if args.stage_supervision:
                stage_fit = fit_stage_head(
                    model,
                    train,
                    valid,
                    stage_arrays[0],
                    stage_arrays[1],
                    epochs=args.stage_epochs,
                    patience=args.patience,
                    seed=args.seed,
                )
                _, _, valid_stage_prob = infer(model, valid, args.horizon, return_stages=True)
                _, _, test_stage_prob = infer(model, test, args.horizon, return_stages=True)
                stage_rows = []
                for j, name in enumerate(STAGES):
                    vknown = stage_arrays[1][:, :, j] >= 0
                    tknown = stage_arrays[2][:, :, j] >= 0
                    vy = stage_arrays[1][:, :, j][vknown]
                    vp = valid_stage_prob[:, :, j][vknown]
                    supported = len(np.unique(vy)) == 2 and vknown.any()
                    if supported:
                        stage_policy = select_policy(vy.astype(int), vp, args.fpr_budget)
                        stage_threshold = stage_policy.get("threshold")
                    else:
                        stage_policy = {"threshold": None, "status": "insufficient_stage_validation_support"}
                        stage_threshold = None
                    stage_rows.append({
                        "stage": name,
                        "mitre": MITRE[j],
                        "validation_policy": stage_policy,
                        "test": metrics(
                            stage_arrays[2][:, :, j][tknown],
                            test_stage_prob[:, :, j][tknown],
                            stage_threshold if stage_threshold is not None else 1.000001,
                        ),
                    })
                result["stage_training"] = stage_fit
                result["supervised_stages"] = stage_rows
            else:
                result["supervised_stages"] = []

            np.savez_compressed(
                out / f"{architecture}_test_predictions.npz",
                probabilities=test_risk,
                raw_probabilities=raw_test_risk,
                labels=test[4],
                state_prediction=mean_test,
                state_target=test[3],
                example_indices=np.asarray(splits[2]),
                history_clean=clean_test,
            )

        metadata = {
            "schema": SCHEMA,
            "features": FEATURES,
            "architecture": architecture,
            "history": args.history,
            "horizon": args.horizon,
            "mode": datasets[0]["metadata"]["mode"],
            "max_nodes": datasets[0]["metadata"]["max_nodes"],
            "window_seconds": datasets[0]["metadata"]["window_seconds"],
            "source_hashes": [d["metadata"]["source_sha256"] for d in datasets],
            "training_campaigns": manifest["train"],
            "validation_campaigns": manifest["validation"],
            "final_test_campaigns": manifest["test"],
            "training_objective": "state_mse_then_frozen_risk_head",
            "state_head_trained": True,
            "risk_head_trained": bool(result["risk_head_trained"]),
            "risk_output_permitted": False,
            "stage_supervised": bool(args.stage_supervision and result["risk_head_trained"]),
            "runtime_evidence": "network-only",
            "unknown_labels_masked": True,
            "automatic_containment_approved": False,
            "evaluation_scope": "new_predeclared_holdout",
        }
        model.save(out / f"{architecture}.npz", metadata)
        result["training_seconds"] = round(time.monotonic() - started, 2)
        report["models"][architecture] = result

    report["checkpoint_sha256"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob("*.npz")
    }
    (out / "metrics.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", nargs="+", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--history", type=int, default=8)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--stride", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--state-epochs", type=int, default=40)
    parser.add_argument("--risk-epochs", type=int, default=30)
    parser.add_argument("--stage-epochs", type=int, default=30)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--fpr-budget", type=float, default=0.01)
    parser.add_argument("--stage-supervision", action="store_true")
    args = parser.parse_args()
    if args.history != 8 or args.horizon != 4:
        parser.error("V45 protocol is frozen at 8 observed and 4 future windows")
    if not 0 < args.fpr_budget <= 0.01:
        parser.error("V45 FPR budget cannot exceed 1%")
    run(args)


if __name__ == "__main__":
    main()
