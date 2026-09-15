"""Training-only hard-negative mining for verified campaign risk readouts."""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler


def training_only_hard_negative_weights(X, y, groups, *, folds=5, threshold=0.5, weight=3.0, random_state=42):
    X = np.asarray(X, dtype=float); y = np.asarray(y, dtype=int); groups = np.asarray(groups)
    if len(X) != len(y) or len(y) != len(groups):
        raise ValueError("X/y/groups length mismatch")
    if set(np.unique(y)) - {0, 1}:
        raise ValueError("Hard-negative mining accepts only known binary training labels")
    unique_groups = np.unique(groups)
    if len(unique_groups) < 2:
        raise ValueError("At least two independent training groups are required")
    n_splits = min(int(folds), len(unique_groups))
    oof = np.full(len(y), np.nan, dtype=float)
    cv = GroupKFold(n_splits=n_splits)
    for tr, va in cv.split(X, y, groups):
        if len(np.unique(y[tr])) < 2:
            raise ValueError("OOF training fold lacks both classes")
        scaler = StandardScaler().fit(X[tr])
        model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state)
        model.fit(scaler.transform(X[tr]), y[tr])
        oof[va] = model.predict_proba(scaler.transform(X[va]))[:, 1]
    if not np.isfinite(oof).all():
        raise ValueError("Incomplete OOF predictions")
    hard = (y == 0) & (oof >= float(threshold))
    weights = np.ones(len(y), dtype=float)
    weights[hard] = float(weight)
    return {
        "weights": weights,
        "oof_probability": oof,
        "hard_negative_mask": hard,
        "hard_negative_count": int(hard.sum()),
        "scope": "training_groups_only",
    }
