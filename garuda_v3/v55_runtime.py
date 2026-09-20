"""Portable V55 joint-family scorer with no pickle deserialization.

The runtime implements the frozen V55 fusion selected on development pair holdouts:
nonlinear temporal transfer + future-state novelty + transition energy. Scores are
benign-tail evidence, not attack probabilities, and automatic containment is disabled.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import sklearn
import torch
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import HISTORY, HORIZON, anomaly_score, build_world_model
from .v48_unseen_fusion import tail_evidence
from .v55_nonlinear_joint_generalization import temporal_history_features

SCHEMA = "garuda.v55.joint-fold.v1"
V55_COMPONENTS = (
    "future_state_novelty",
    "transition_energy",
    "nonlinear_temporal_transfer",
)


def fit_nonlinear_runtime(X, target, split, seed):
    tr = np.where(split["train"])[0]
    if len(tr) < 50 or len(np.unique(np.asarray(target)[tr])) < 2:
        raise ValueError("V55 nonlinear head requires two-class development support")

    feat = temporal_history_features(X)
    feat[~np.isfinite(feat)] = np.nan
    med = np.nanmedian(feat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = med[np.where(bad)[1]]

    model = ExtraTreesClassifier(
        n_estimators=240,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=1,
    )
    model.fit(feat[tr], np.asarray(target)[tr])
    return model.predict_proba(feat)[:, 1], {"model": model, "median": med}


def _forest_arrays(runtime):
    model = runtime["model"]
    offsets = [0]
    left = []
    right = []
    feature = []
    threshold = []
    values = []

    for est in model.estimators_:
        tree = est.tree_
        left.append(tree.children_left.astype(np.int32))
        right.append(tree.children_right.astype(np.int32))
        feature.append(tree.feature.astype(np.int32))
        threshold.append(tree.threshold.astype(np.float64))
        value = np.asarray(tree.value, dtype=np.float64).reshape(tree.node_count, -1)
        values.append(value)
        offsets.append(offsets[-1] + tree.node_count)

    return {
        "forest_offsets": np.asarray(offsets, dtype=np.int64),
        "forest_left": np.concatenate(left),
        "forest_right": np.concatenate(right),
        "forest_feature": np.concatenate(feature),
        "forest_threshold": np.concatenate(threshold),
        "forest_value": np.concatenate(values, axis=0),
        "forest_classes": np.asarray(model.classes_),
        "forest_median": np.asarray(runtime["median"], dtype=np.float64),
    }


def export_v55(
    path,
    *,
    world,
    base_components,
    nonlinear_runtime,
    config,
    threshold,
    feature_names,
    seed,
):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=False)

    scaler = world["runtime_scaler"]
    arrays = {
        "state_median": np.asarray(world["imputer_median"]),
        "state_mean": scaler.mean_,
        "state_scale": scaler.scale_,
        "future_center": base_components["runtime_references"]["future"][0],
        "future_scale": base_components["runtime_references"]["future"][1],
    }
    arrays.update(_forest_arrays(nonlinear_runtime))

    for key, value in world["runtime_model"].state_dict().items():
        arrays["weight." + key] = value.cpu().numpy()

    cal = base_components["cal_benign"]
    pred = world["pred"]
    persistence = world["persistence"]
    delta = pred - persistence
    raw_future = anomaly_score(pred, arrays["future_center"], arrays["future_scale"])
    raw_energy = np.mean(delta * delta, axis=(1, 2))
    nonlinear_score = nonlinear_runtime["score"]

    arrays["cal.future_state_novelty"] = raw_future[cal]
    arrays["cal.transition_energy"] = raw_energy[cal]
    arrays["cal.nonlinear_temporal_transfer"] = nonlinear_score[cal]

    np.savez_compressed(path / "arrays.npz", **arrays)
    raw = (path / "arrays.npz").read_bytes()
    manifest = {
        "schema": SCHEMA,
        "sklearn_version": sklearn.__version__,
        "torch_version": torch.__version__,
        "history": HISTORY,
        "horizon": HORIZON,
        "window_seconds": 60,
        "feature_names": list(feature_names),
        "seed": int(seed),
        "weights": config["weights"],
        "threshold": float(threshold),
        "state_gate_passed": bool(world["state_gate_passed"]),
        "automatic_containment": False,
        "score_kind": "benign_tail_evidence_not_probability",
        "arrays_sha256": hashlib.sha256(raw).hexdigest(),
    }
    (path / "manifest.json").write_text(
        json.dumps(manifest, indent=2, allow_nan=False) + "\n"
    )
    return manifest


def _forest_predict_proba(arrays, feat):
    """Reproduce sklearn tree inference without unpickling estimators.

    sklearn's tree prediction path casts feature matrices to its internal float32
    DTYPE before comparing values with stored split thresholds. We intentionally
    mirror that conversion after applying the float64 training-time imputation;
    otherwise values very close to a threshold can take a different branch.
    """
    feat = np.asarray(feat, dtype=np.float64).copy()
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = arrays["forest_median"][np.where(bad)[1]]

    # Critical parity rule: sklearn Tree.predict uses float32 input semantics.
    feat = feat.astype(np.float32, copy=False)

    offsets = arrays["forest_offsets"]
    total = np.zeros(len(feat), dtype=np.float64)
    classes = arrays["forest_classes"].tolist()
    if 1 not in classes:
        raise ValueError("V55 forest missing positive class")
    pos = classes.index(1)

    for tree_index in range(len(offsets) - 1):
        lo = int(offsets[tree_index])
        node = np.zeros(len(feat), dtype=np.int32)

        while True:
            global_node = lo + node
            left = arrays["forest_left"][global_node]
            leaf = left < 0
            if bool(np.all(leaf)):
                break

            row_index = np.where(~leaf)[0]
            active_global = global_node[row_index]
            feature_index = arrays["forest_feature"][active_global]
            go_left = (
                feat[row_index, feature_index]
                <= arrays["forest_threshold"][active_global]
            )
            node[row_index] = np.where(
                go_left,
                arrays["forest_left"][active_global],
                arrays["forest_right"][active_global],
            )

        values = arrays["forest_value"][lo + node]
        denominator = values.sum(axis=1)
        probability = np.divide(
            values[:, pos],
            denominator,
            out=np.zeros(len(values), dtype=float),
            where=denominator > 0,
        )
        total += probability

    return total / max(1, len(offsets) - 1)


class V55Runtime:
    def __init__(self, path):
        path = Path(path)
        self.path = path
        self.meta = json.loads((path / "manifest.json").read_text())

        if self.meta.get("schema") != SCHEMA:
            raise ValueError("Incompatible V55 runtime schema")
        if (
            self.meta["sklearn_version"] != sklearn.__version__
            or self.meta["torch_version"] != torch.__version__
        ):
            raise ValueError(
                "V55 dependency versions differ; revalidate export parity before use"
            )

        raw = (path / "arrays.npz").read_bytes()
        if hashlib.sha256(raw).hexdigest() != self.meta["arrays_sha256"]:
            raise ValueError("V55 artifact checksum mismatch")
        if (
            self.meta["history"],
            self.meta["horizon"],
            self.meta["window_seconds"],
        ) != (HISTORY, HORIZON, 60):
            raise ValueError("Incompatible V55 time contract")

        with np.load(path / "arrays.npz", allow_pickle=False) as loaded:
            self.a = {key: loaded[key].copy() for key in loaded.files}

        self.model = build_world_model(len(self.meta["feature_names"]))
        self.model.load_state_dict(
            {
                key[7:]: torch.from_numpy(value)
                for key, value in self.a.items()
                if key.startswith("weight.")
            }
        )
        self.model.eval()

    def predict(self, X, feature_names, window_seconds=60):
        if list(feature_names) != self.meta["feature_names"] or int(window_seconds) != 60:
            raise ValueError("V55 requires exact ordered minute-state features")

        X = np.asarray(X, dtype=np.float32)
        if (
            X.ndim != 3
            or X.shape[1:] != (HISTORY, len(feature_names))
            or not len(X)
        ):
            raise ValueError("Invalid V55 history shape")

        arrays = self.a
        scaled = X.copy()
        bad = ~np.isfinite(scaled)
        scaled[bad] = arrays["state_median"][np.where(bad)[-1]]

        scaler = StandardScaler()
        scaler.mean_ = arrays["state_mean"]
        scaler.scale_ = arrays["state_scale"]
        scaler.n_features_in_ = len(feature_names)
        scaled = scaler.transform(
            scaled.reshape(-1, len(feature_names))
        ).reshape(scaled.shape)

        with torch.no_grad():
            pred = self.model(torch.from_numpy(scaled)).numpy()

        persistence = np.repeat(scaled[:, -1:, :], HORIZON, axis=1)
        delta = pred - persistence
        raw = {
            "future_state_novelty": anomaly_score(
                pred,
                arrays["future_center"],
                arrays["future_scale"],
            ),
            "transition_energy": np.mean(delta * delta, axis=(1, 2)),
            "nonlinear_temporal_transfer": _forest_predict_proba(
                arrays,
                temporal_history_features(X),
            ),
        }
        evidence = {
            key: tail_evidence(arrays["cal." + key], value)
            for key, value in raw.items()
        }

        score = np.zeros(len(X), dtype=float)
        for key, weight in self.meta["weights"].items():
            if float(weight):
                if key not in evidence:
                    raise ValueError(f"V55 runtime missing weighted component {key}")
                score += float(weight) * evidence[key]

        alert = (
            score >= float(self.meta["threshold"])
        ) & bool(self.meta["state_gate_passed"])

        return {
            "state_scaled": pred,
            "score": score,
            "alert": alert,
            "components": evidence,
            "transition_feature_energy": np.mean(delta * delta, axis=1),
            "automatic_containment": False,
            "score_kind": "benign_tail_evidence_not_probability",
        }
