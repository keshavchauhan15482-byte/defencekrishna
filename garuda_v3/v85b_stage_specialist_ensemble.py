"""V85b runner: fixes the V85 specialist logistic-C parser without changing the protocol."""
from __future__ import annotations

from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis

from . import v85_stage_specialist_ensemble as impl


def make_binary(kind: str):
    if kind.startswith("logistic_c"):
        token = kind[len("logistic_c"):]
        C = float(token.replace("p", "."))
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=C, class_weight="balanced", max_iter=3000,
                solver="liblinear", random_state=20260921,
            )),
        ])
    if kind == "lda_shrinkage":
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LinearDiscriminantAnalysis(solver="lsqr", shrinkage="auto")),
        ])
    if kind.startswith("extra_trees_leaf"):
        leaf = int(kind.rsplit("leaf", 1)[1])
        return ExtraTreesClassifier(
            n_estimators=500, max_features="sqrt", min_samples_leaf=leaf,
            class_weight="balanced", random_state=20260921 + leaf, n_jobs=2,
        )
    raise KeyError(kind)


impl.make_binary = make_binary


if __name__ == "__main__":
    impl.main()
