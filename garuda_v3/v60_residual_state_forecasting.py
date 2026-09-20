"""V60 residual state-forecasting diagnostic.

Purpose
-------
Address the weakness seen in V58 where the legacy absolute-state LSTM did not beat
persistence consistently on the RDoS holdout slice. V60 changes only the state
forecasting model: it predicts residual motion around the persistence baseline and
selects a conservative residual/trend blend on leakage-safe validation data only.

RDoS has already been inspected in V58, so V60's RDoS result is explicitly diagnostic,
not a fresh independent claim. Final external validation must come from a different
untouched dataset/campaign.
"""
from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HORIZON,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    fit_transform_state,
    make_sequences,
    parse_time,
    sha256,
    temporal_masks,
    train_world_model,
)
from .v48_strict_runner import canonical_family_name
from .v54_joint_family_generalization import _future_presence, _joint_reserve_split

BLEND_GRID = tuple(
    (alpha, beta)
    for alpha in (0.0, 0.25, 0.5, 0.75, 1.0)
    for beta in (0.0, 0.25, 0.5)
)


def _build_residual_model(features: int):
    import torch.nn as nn

    class ResidualWorld(nn.Module):
        def __init__(self, n_features: int):
            super().__init__()
            self.norm = nn.LayerNorm(n_features)
            self.rnn = nn.LSTM(n_features, 48, batch_first=True)
            self.head = nn.Sequential(
                nn.Linear(48, 64),
                nn.SiLU(),
                nn.Linear(64, HORIZON * n_features),
            )

        def forward(self, x):
            z = self.norm(x)
            _, (h, _) = self.rnn(z)
            return self.head(h[-1]).reshape(len(x), HORIZON, x.shape[-1])

    return ResidualWorld(features)


def _trend_from_history(Xs: np.ndarray) -> np.ndarray:
    """Damped recent trend anchored at the last observed state."""
    recent = Xs[:, -1, :] - Xs[:, -2, :]
    steps = np.arange(1, HORIZON + 1, dtype=np.float32)[None, :, None]
    damping = np.minimum(steps, 2.0)
    return Xs[:, -1:, :] + damping * recent[:, None, :]


def _mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


def train_residual_world_model(X, future, train_mask, val_mask, seed, epochs=18):
    import torch
    import torch.nn as nn

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))

    tr = np.where(train_mask)[0]
    va = np.where(val_mask)[0]
    if len(tr) < 50 or len(va) < 20:
        raise ValueError(f"State support too small train={len(tr)} validation={len(va)}")

    transformed, med, scaler = fit_transform_state(X[tr], future[tr], [X, future])
    Xs, Fs = transformed
    persistence = np.repeat(Xs[:, -1:, :], HORIZON, axis=1)
    residual_target = Fs - persistence
    trend = _trend_from_history(Xs)

    model = _build_residual_model(X.shape[-1])
    opt = torch.optim.AdamW(model.parameters(), lr=0.0015, weight_decay=1e-4)
    loss_fn = nn.SmoothL1Loss(beta=0.25)
    xtr = torch.tensor(Xs[tr])
    rtr = torch.tensor(residual_target[tr])
    xva = torch.tensor(Xs[va])

    best_state = None
    best_val = None
    stale = 0
    patience = 6
    batch = 256
    rng = np.random.default_rng(seed)

    for _epoch in range(epochs):
        order = rng.permutation(len(tr))
        model.train()
        for start in range(0, len(order), batch):
            ids = order[start:start + batch]
            pred_r = model(xtr[ids])
            loss = loss_fn(pred_r, rtr[ids])
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()

        model.eval()
        with torch.no_grad():
            val_r = model(xva).cpu().numpy()
        # Early stopping uses the raw residual correction only; final blend is frozen
        # after training using the same validation set and a fixed predeclared grid.
        val_pred = persistence[va] + val_r
        val_mse = float(np.mean((val_pred - Fs[va]) ** 2))
        if best_val is None or val_mse < best_val - 1e-7:
            best_val = val_mse
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= patience:
                break

    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        residual_pred = model(torch.tensor(Xs)).cpu().numpy()

    # Validation-only conservative blend. alpha controls learned residual motion;
    # beta controls a deterministic short trend continuation. Persistence is the anchor.
    candidates = []
    for alpha, beta in BLEND_GRID:
        pred = persistence + alpha * residual_pred + beta * (trend - persistence)
        val_mse = float(np.mean((pred[va] - Fs[va]) ** 2))
        candidates.append((val_mse, alpha, beta))
    candidates.sort(key=lambda x: (x[0], x[1] + x[2], x[1], x[2]))
    selected_val_mse, alpha, beta = candidates[0]
    pred = persistence + alpha * residual_pred + beta * (trend - persistence)

    val_persistence_mse = float(np.mean((persistence[va] - Fs[va]) ** 2))
    return {
        "pred": pred,
        "future_scaled": Fs,
        "persistence": persistence,
        "validation_mse": float(selected_val_mse),
        "validation_persistence_mse": val_persistence_mse,
        "state_gate_passed": bool(selected_val_mse < val_persistence_mse),
        "blend_alpha": float(alpha),
        "trend_beta": float(beta),
        "imputer_median": med,
        "runtime_scaler": scaler,
        "runtime_model": model,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--holdout-family", default="rdos")
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V60 evidence is immutable")
    out.mkdir(parents=True)

    csv = Path(args.csv)
    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    seq = make_sequences(state, names)
    masks, boundaries = temporal_masks(seq["cutoff"])

    holdout = canonical_family_name(args.holdout_family)
    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})
    if holdout not in available:
        raise RuntimeError(f"Holdout {holdout!r} missing; available={available}")

    split = _joint_reserve_split(seq, masks, [holdout])
    positive = _future_presence(seq, holdout)
    negative = split["test_negative"]
    test_mask = positive | negative

    rows = {}
    for seed in args.seeds:
        print(f"V60 seed={seed}", flush=True)
        legacy = train_world_model(
            seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=args.epochs
        )
        residual = train_residual_world_model(
            seq["X"], seq["future"], split["train"], split["calibration"], seed, epochs=args.epochs
        )
        row = {
            "seed": int(seed),
            "selected_blend": {
                "alpha": residual["blend_alpha"],
                "trend_beta": residual["trend_beta"],
            },
            "validation": {
                "legacy_mse": legacy["validation_mse"],
                "residual_mse": residual["validation_mse"],
                "persistence_mse": residual["validation_persistence_mse"],
                "residual_beats_persistence": residual["state_gate_passed"],
            },
            "test_all": {
                "legacy_mse": _mse(legacy["pred"], legacy["future_scaled"], test_mask),
                "residual_mse": _mse(residual["pred"], residual["future_scaled"], test_mask),
                "persistence_mse": _mse(residual["persistence"], residual["future_scaled"], test_mask),
            },
            "test_positive_only": {
                "legacy_mse": _mse(legacy["pred"], legacy["future_scaled"], positive),
                "residual_mse": _mse(residual["pred"], residual["future_scaled"], positive),
                "persistence_mse": _mse(residual["persistence"], residual["future_scaled"], positive),
            },
            "test_clean_negative_only": {
                "legacy_mse": _mse(legacy["pred"], legacy["future_scaled"], negative),
                "residual_mse": _mse(residual["pred"], residual["future_scaled"], negative),
                "persistence_mse": _mse(residual["persistence"], residual["future_scaled"], negative),
            },
        }
        row["test_all"]["legacy_beats_persistence"] = bool(
            row["test_all"]["legacy_mse"] < row["test_all"]["persistence_mse"]
        )
        row["test_all"]["residual_beats_persistence"] = bool(
            row["test_all"]["residual_mse"] < row["test_all"]["persistence_mse"]
        )
        rows[str(seed)] = row

    residual_pass = sum(int(r["test_all"]["residual_beats_persistence"]) for r in rows.values())
    legacy_pass = sum(int(r["test_all"]["legacy_beats_persistence"]) for r in rows.values())
    test_improvement = []
    positive_improvement = []
    for r in rows.values():
        pmse = r["test_all"]["persistence_mse"]
        rmse = r["test_all"]["residual_mse"]
        test_improvement.append((pmse - rmse) / pmse if pmse else 0.0)
        ppmse = r["test_positive_only"]["persistence_mse"]
        prmse = r["test_positive_only"]["residual_mse"]
        positive_improvement.append((ppmse - prmse) / ppmse if ppmse else 0.0)

    report = {
        "protocol": "V60 persistence-anchored residual state forecasting diagnostic",
        "claim_boundary": (
            "RDoS was already inspected in V58. This is a post-diagnostic engineering test, "
            "not a fresh independent holdout claim. Blend selection uses calibration data only."
        ),
        "source_sha256": sha256(csv),
        "holdout_family": holdout,
        "seeds": list(args.seeds),
        "support": {
            "train": int(split["train"].sum()),
            "calibration": int(split["calibration"].sum()),
            "policy": int(split["policy"].sum()),
            "test_positive": int(positive.sum()),
            "test_negative": int(negative.sum()),
        },
        "rows": rows,
        "summary": {
            "legacy_test_gate_passed_seeds": int(legacy_pass),
            "residual_test_gate_passed_seeds": int(residual_pass),
            "mean_test_mse_improvement_vs_persistence": float(np.mean(test_improvement)),
            "mean_positive_mse_improvement_vs_persistence": float(np.mean(positive_improvement)),
        },
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "boundaries": boundaries,
        },
        "labels": {"binary": binary_col, "family": family_col, "profiles": profiles},
        "network_only_feature_audit": {"raw_selected": feature_cols, "audit": feature_audit},
        "source_group_column": src_col,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
