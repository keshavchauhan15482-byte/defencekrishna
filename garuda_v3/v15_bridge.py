"""Bridge fresh V15 evidence into the real Krishna Defence runtime.

The X-IIoTID V15 branch is not a drop-in checkpoint for the existing Garuda v3
10-second graph schema.  This bridge deliberately separates measured evidence
from runtime compatibility and containment authority so a strong offline result
cannot silently become an enforcement decision.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LSTM = ROOT / "datasets" / "v15" / "xiiotid_lstm_results.json"
DEFAULT_GNN = ROOT / "datasets" / "v15" / "xiiotid_gnn_results.json"


class V15EvidenceBridge:
    def __init__(self, lstm_path: Path | str = DEFAULT_LSTM, gnn_path: Path | str = DEFAULT_GNN):
        self.lstm_path = Path(lstm_path)
        self.gnn_path = Path(gnn_path)
        self.lstm = self._load(self.lstm_path, "krishna-v15-xiiotid-temporal-pilot-v2")
        self.gnn = self._load(self.gnn_path, "krishna-v15-xiiotid-graphsage-lstm-v1")
        self._validate_common_provenance()

    @staticmethod
    def _load(path: Path, schema: str) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Missing V15 evidence: {path}")
        data = json.loads(path.read_text())
        if data.get("schema") != schema:
            raise ValueError(f"Unexpected V15 schema in {path}")
        if data.get("provenance", {}).get("sha256") != "7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0":
            raise ValueError("V15 X-IIoTID provenance hash mismatch")
        return data

    def _validate_common_provenance(self) -> None:
        a, b = self.lstm["provenance"], self.gnn["provenance"]
        for key in ("filename", "bytes", "sha256", "rows", "columns"):
            if a[key] != b[key]:
                raise ValueError(f"V15 evidence provenance disagreement: {key}")
        if self.lstm["protocol"]["test"] != self.gnn["protocol"]["test"]:
            raise ValueError("V15 branches do not share the same untouched test population")

    @property
    def runtime_graph_schema_compatible(self) -> bool:
        return bool(self.lstm["protocol"].get("runtime_graph_schema_compatible", False))

    @property
    def network_only_feature_audit_passed(self) -> bool:
        return bool(self.lstm["protocol"].get("network_only_feature_audit_passed", False))

    @property
    def clean_history_future_positive_n(self) -> int:
        return min(int(seed["clean_history_future_positive_n"]) for seed in self.lstm["seeds"].values())

    @property
    def autonomous_unknown_containment_approved(self) -> bool:
        # Every condition is intentionally necessary.  Current V15 evidence fails
        # three of them: no clean-history onset positives, no network-only audit,
        # and no runtime schema compatibility.
        return bool(
            self.lstm.get("production_containment_approved", False)
            and self.clean_history_future_positive_n > 0
            and self.network_only_feature_audit_passed
            and self.runtime_graph_schema_compatible
        )

    @property
    def deployable_risk_checkpoint_available(self) -> bool:
        # V15 training evidence currently proves the experiment, not a checkpoint
        # that can consume the live Garuda v3 graph request schema.
        return False

    def public_status(self) -> Dict[str, Any]:
        lm = self.lstm["three_seed_mean"]
        gm = self.gnn["three_seed_mean"]
        return {
            "component": "Garuda AI V15 evidence bridge",
            "role": "temporal future-malicious-traffic validation branch",
            "lstm": {
                "observed_fpr": lm["fpr"],
                "recall": lm["recall"],
                "precision": lm["precision"],
                "f1": lm["f1"],
                "pr_auc": lm["pr_auc"],
                "brier": lm["brier"],
            },
            "gnn_lstm": {
                "observed_fpr": gm["fpr"],
                "recall": gm["recall"],
                "precision": gm["precision"],
                "f1": gm["f1"],
                "pr_auc": gm["pr_auc"],
                "brier": gm["brier"],
            },
            "test_support": self.lstm["protocol"]["test"],
            "history_minutes": self.lstm["protocol"]["history_minutes"],
            "future_horizon_minutes": self.lstm["protocol"]["future_horizon_minutes"],
            "dataset_sha256": self.lstm["provenance"]["sha256"],
            "clean_history_future_positive_n": self.clean_history_future_positive_n,
            "pre_compromise_warning_verified": False,
            "network_only_feature_audit_passed": self.network_only_feature_audit_passed,
            "runtime_graph_schema_compatible": self.runtime_graph_schema_compatible,
            "deployable_risk_checkpoint_available": self.deployable_risk_checkpoint_available,
            "autonomous_unknown_containment_approved": self.autonomous_unknown_containment_approved,
            "integration_mode": "evidence_and_policy_guard; existing Garuda v3 graph forecaster remains runtime model",
            "limitation": self.lstm["evidence_limit"],
        }

    def decorate_forecast(self, forecast: Dict[str, Any]) -> Dict[str, Any]:
        forecast = dict(forecast)
        forecast["garuda_v15"] = self.public_status()
        return forecast
