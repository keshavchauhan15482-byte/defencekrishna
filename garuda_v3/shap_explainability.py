"""SHAP attribution for Garuda world-model risk forecasts.

The explanation unit is an observed input feature channel across the frozen history.
A coalition turns each channel on (observed value) or off (reference value) while
keeping graph adjacency and observation masks fixed.  The model sees no future label,
future graph, or target.  These are model attributions, not causal explanations.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

import numpy as np

from .data import FEATURES
from .model import GraphWorldModel


def channel_coalition_predictor(
    model: GraphWorldModel,
    x: np.ndarray,
    adj: np.ndarray,
    mask: np.ndarray,
    *,
    horizon: int,
    reference: np.ndarray | None = None,
    target_horizon: int | None = None,
) -> Callable[[np.ndarray], np.ndarray]:
    """Create a 22-channel coalition -> forecast-risk function for one history."""
    x = np.asarray(x, dtype=np.float32)
    adj = np.asarray(adj, dtype=np.float32)
    mask = np.asarray(mask, dtype=np.float32)
    if x.ndim != 4 or x.shape[0] != 1:
        raise ValueError("x must contain exactly one [batch,time,node,feature] history")
    if adj.shape[:3] != x.shape[:3] or adj.shape[-1] != x.shape[2]:
        raise ValueError("adj shape must match batch/time/node dimensions")
    if mask.shape != x.shape[:3]:
        raise ValueError("mask shape must match batch/time/node dimensions")
    if x.shape[-1] != len(FEATURES):
        raise ValueError("feature dimension does not match Garuda feature contract")
    if horizon < 1:
        raise ValueError("horizon must be positive")
    if target_horizon is not None and not 0 <= target_horizon < horizon:
        raise ValueError("target_horizon is out of range")

    observed = x[0]
    if reference is None:
        base = np.zeros_like(observed)
    else:
        ref = np.asarray(reference, dtype=np.float32)
        if ref.shape == (len(FEATURES),):
            base = np.broadcast_to(ref, observed.shape).copy()
        elif ref.shape == observed.shape:
            base = ref.copy()
        else:
            raise ValueError("reference must be [feature] or [time,node,feature]")
        base *= mask[0, :, :, None]

    def predict(coalitions: np.ndarray) -> np.ndarray:
        z = np.asarray(coalitions, dtype=np.float32)
        if z.ndim == 1:
            z = z[None, :]
        if z.ndim != 2 or z.shape[1] != len(FEATURES):
            raise ValueError("coalitions must be [samples, feature_channels]")
        if not np.isfinite(z).all():
            raise ValueError("coalitions contain non-finite values")
        mixed = base[None] + z[:, None, None, :] * (observed[None] - base[None])
        a = np.repeat(adj, len(z), axis=0)
        m = np.repeat(mask, len(z), axis=0)
        _mu, _sigma, risk = model.forward(mixed, a, m, horizon=horizon)
        values = np.asarray(risk.data, dtype=np.float64)
        return values[:, target_horizon] if target_horizon is not None else values.max(axis=1)

    return predict


def explain(
    model: GraphWorldModel,
    x: np.ndarray,
    adj: np.ndarray,
    mask: np.ndarray,
    *,
    horizon: int,
    nsamples: int | str = "auto",
    target_horizon: int | None = None,
    reference: np.ndarray | None = None,
) -> dict:
    try:
        import shap
    except ImportError as exc:
        raise RuntimeError("SHAP is not installed; install the repository requirements") from exc

    predictor = channel_coalition_predictor(
        model, x, adj, mask, horizon=horizon, reference=reference, target_horizon=target_horizon
    )
    background = np.zeros((1, len(FEATURES)), dtype=np.float32)
    foreground = np.ones((1, len(FEATURES)), dtype=np.float32)
    explainer = shap.KernelExplainer(predictor, background)
    raw = explainer.shap_values(foreground, nsamples=nsamples)
    values = np.asarray(raw, dtype=np.float64)
    if values.ndim > 1:
        values = values.reshape(-1, values.shape[-1])[0]
    if values.shape != (len(FEATURES),):
        raise RuntimeError(f"Unexpected SHAP output shape: {values.shape}")

    order = np.argsort(np.abs(values))[::-1]
    predicted = float(predictor(foreground)[0])
    baseline = float(predictor(background)[0])
    return {
        "schema": "garuda-world-model-shap-v1",
        "target": "max forecast risk" if target_horizon is None else f"forecast risk horizon_index={target_horizon}",
        "predicted_risk": predicted,
        "reference_risk": baseline,
        "feature_attributions": [
            {"feature": FEATURES[int(i)], "shap_value": float(values[int(i)]), "absolute_shap": float(abs(values[int(i)]))}
            for i in order
        ],
        "method": "Kernel SHAP over observed input feature-channel coalitions; graph topology and masks fixed",
        "claim_boundary": "Model attribution only; not causal evidence and not a substitute for unseen-holdout or pre-compromise validation.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--history-npz", required=True, help="NPZ with x, adj and mask arrays; first example is explained")
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--target-horizon", type=int)
    parser.add_argument("--nsamples", default="auto")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    model, _metadata = GraphWorldModel.load(args.model)
    with np.load(args.history_npz, allow_pickle=False) as z:
        x = z["x"][:1]
        adj = z["adj"][:1]
        mask = z["mask"][:1]
    nsamples: int | str = args.nsamples if args.nsamples == "auto" else int(args.nsamples)
    result = explain(model, x, adj, mask, horizon=args.horizon, target_horizon=args.target_horizon, nsamples=nsamples)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
