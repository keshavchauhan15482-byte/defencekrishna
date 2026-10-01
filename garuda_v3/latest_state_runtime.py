"""Pinned live adapter for the V123-qualified PS-complete state forecaster.

This runtime intentionally does NOT replace the existing risk/response checkpoint.
V116/V118/V122/V123 certify future network-state forecasting only: the V116 checkpoint
has no trained risk head and no supervised stage head.  The adapter therefore exposes
only 34-feature future-state trajectories from raw PCAP telemetry and keeps risk,
MITRE-stage, and autonomous-response claims out of this path.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES
from .v101_packet_graph_recovery import HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, pooled_history
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import RELATIVE_FEATURES, RELATIVE_SCHEMA, RAW_SCHEMA, inverse_pooled
from .v122_semantic_support_contract import semantic_decisions

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'garuda_v3/artifacts/certification/v116/gnn_lstm_raw_metric_relative_candidate.npz'
TRANSFORM = ROOT / 'garuda_v3/artifacts/certification/v116/relative_transform.json'
CALIBRATION = ROOT / 'garuda_v3/artifacts/certification/v118/innovation_calibration.json'
SEMANTIC = ROOT / 'garuda_v3/artifacts/certification/v122/semantic_support_contract.json'
V123_RESULT = ROOT / 'garuda_v3/artifacts/certification/v123/one_shot_result.json'

EXPECTED = {
    'model': '1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c',
    'transform': '6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643',
    'calibration': 'c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701',
    'semantic': '2b248bdb0c9504598d8feecb5a09bdcb322db605872839c684f235c938fec564',
}


class LatestStateRuntimeError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


class LatestStateForecastService:
    """State-only live inference using the exact V123 frozen runtime chain."""

    def __init__(self):
        for label, path in (
            ('model', MODEL), ('transform', TRANSFORM),
            ('calibration', CALIBRATION), ('semantic', SEMANTIC),
        ):
            if not path.is_file() or _sha256(path) != EXPECTED[label]:
                raise LatestStateRuntimeError(f'Pinned V123 {label} artifact mismatch')

        self.transform = json.loads(TRANSFORM.read_text())
        self.calibration = json.loads(CALIBRATION.read_text())
        self.semantic_contract = json.loads(SEMANTIC.read_text())
        self.external_result = json.loads(V123_RESULT.read_text())
        self.model, self.meta = GraphWorldModel.load(MODEL)
        self.alpha = float(self.calibration['alpha'])

        if self.model.schema != RELATIVE_SCHEMA or self.model.f != len(FEATURES):
            raise LatestStateRuntimeError('V123 model schema/feature contract mismatch')
        if self.meta.get('raw_input_schema') != RAW_SCHEMA:
            raise LatestStateRuntimeError('V123 raw input schema mismatch')
        if list(self.meta.get('features', [])) != list(FEATURES):
            raise LatestStateRuntimeError('V123 feature ordering mismatch')
        if not self.meta.get('packet_features_trained') or not self.meta.get('ps_complete_features_trained'):
            raise LatestStateRuntimeError('V123 model is not packet/PS-complete trained')
        if self.meta.get('risk_head_trained') is not False or self.model.stage_count != 0:
            raise LatestStateRuntimeError('V123 promotion must remain state-only')
        if self.semantic_contract.get('status') != 'FROZEN':
            raise LatestStateRuntimeError('V122 semantic support contract is not frozen')
        if self.external_result.get('status') != 'PASS':
            raise LatestStateRuntimeError('V123 fresh external evidence is not PASS')
        if not (0.0 < self.alpha <= 1.0):
            raise LatestStateRuntimeError('Invalid V118 innovation calibration')
        for p in self.model.parameters():
            p.requires_grad = False
        self.experimental_heads = None
        head_folder = os.environ.get('GARUDA_COUPLED_HEAD_EXPERIMENT')
        if head_folder:
            from .coupled_heads import ShadowReadout
            self.experimental_heads = ShadowReadout(head_folder, self.model)


    def _relative_history(self, raw_x: np.ndarray, mask: np.ndarray):
        raw_x = np.asarray(raw_x, dtype=np.float32)
        mask = np.asarray(mask, dtype=np.float32)
        pooled = pooled_history(raw_x, mask)
        center = np.median(pooled, axis=1).astype(np.float32)
        scale = np.asarray(self.transform['scale'], dtype=np.float32)
        model_x = raw_x.copy()
        for name in RELATIVE_FEATURES:
            j = FEATURES.index(name)
            model_x[..., j] = (model_x[..., j] - center[:, None, None, j]) / scale[j]
        model_x *= mask[..., None]
        return model_x, center

    def forecast_history(self, raw_x, adj, mask, times):
        raw_x = np.asarray(raw_x, dtype=np.float32)
        adj = np.asarray(adj, dtype=np.float32)
        mask = np.asarray(mask, dtype=np.float32)
        times = np.asarray(times, dtype=np.int64)
        if raw_x.shape != (HISTORY, MAX_NODES, len(FEATURES)):
            raise LatestStateRuntimeError('Expected one 8-window 34-feature PS-complete history')
        if adj.shape != (HISTORY, MAX_NODES, MAX_NODES) or mask.shape != (HISTORY, MAX_NODES):
            raise LatestStateRuntimeError('Latest state runtime graph dimensions mismatch')
        if times.shape != (HISTORY,) or not np.all(np.diff(times) == WINDOW_SECONDS):
            raise LatestStateRuntimeError('Latest state runtime requires contiguous 10-second history')
        if not np.isfinite(raw_x).all() or not np.isfinite(adj).all() or not np.isfinite(mask).all():
            raise LatestStateRuntimeError('Non-finite latest state runtime input')

        bx, ba, bm = raw_x[None], adj[None], mask[None]
        model_x, center = self._relative_history(bx, bm)
        semantic = semantic_decisions(bx, model_x, bm)
        supported = bool(semantic['supported'][0])
        if not supported:
            return {
                'status': 'SHADOW_UNRESOLVED',
                'supported': False,
                'reason': 'V122 semantic runtime contract rejected this telemetry',
                'automatic_containment': False,
                'risk_probability': None,
                'mitre_stage': None,
            }

        mean, sigma, _unused_risk = self.model.forward(model_x, ba, bm, HORIZON)
        model_raw = inverse_pooled(mean.data, center, self.transform)
        persistence = np.repeat(pooled_history(bx, bm)[:, -1:, :], HORIZON, axis=1)
        calibrated = persistence + self.alpha * (model_raw - persistence)
        calibrated = calibrated[0]

        trajectory = []
        for k, state in enumerate(calibrated):
            trajectory.append({
                'horizon_seconds': (k + 1) * WINDOW_SECONDS,
                'state_vector': state.astype(float).tolist(),
            })
        result = {
            'status': 'SUPPORTED_STATE_FORECAST',
            'supported': True,
            'model': 'V116 GraphSAGE+LSTM + V118 innovation calibration',
            'model_sha256': EXPECTED['model'],
            'raw_schema': RAW_SCHEMA,
            'model_schema': RELATIVE_SCHEMA,
            'feature_count': len(FEATURES),
            'feature_names': list(FEATURES),
            'history_seconds': HISTORY * WINDOW_SECONDS,
            'cutoff_epoch_seconds': int(times[-1] + WINDOW_SECONDS),
            'trajectory': trajectory,
            'innovation_alpha': self.alpha,
            'runtime_support': 'V122 semantic support PASS',
            'fresh_external_evidence': {
                'version': 'V123',
                'status': self.external_result['status'],
                'sequences': self.external_result['capture_processing']['aggregate_contiguous_sequences'],
                'semantic_support_fraction': self.external_result['runtime_support']['supported_fraction'],
                'improvement_vs_persistence': self.external_result['state_forecasting']['calibrated_improvement_vs_persistence'],
            },
            'risk_probability': None,
            'mitre_stage': None,
            'automatic_containment': False,
            'claim_boundary': 'Future network-state forecasting only; this state-only checkpoint does not emit attack probability, MITRE stage, or autonomous containment.',
        }
        if self.experimental_heads is not None:
            result['candidate_decision_forecast'] = self.experimental_heads.forecast(model_x, ba, bm)
        return result

    def analyze_pcap(self, raw: bytes, packet_limit: int = 250_000):
        if not raw:
            raise LatestStateRuntimeError('Empty PCAP')
        with tempfile.TemporaryDirectory(prefix='garuda-v123-live-') as tmp:
            path = Path(tmp) / 'capture.pcap'
            path.write_bytes(raw)
            times, x, adj, mask, decoded, audit = tolerant_packet_service_graphs(path, packet_limit)
        # Use the newest contiguous eight-window history. Future windows are never
        # supplied to the model in live mode.
        end = None
        for i in range(len(times), HISTORY - 1, -1):
            if np.all(np.diff(times[i-HISTORY:i]) == WINDOW_SECONDS):
                end = i
                break
        if end is None:
            raise LatestStateRuntimeError('No contiguous 8-window history for V123 live state forecast')
        result = self.forecast_history(x[end-HISTORY:end], adj[end-HISTORY:end], mask[end-HISTORY:end], times[end-HISTORY:end])
        result['ingestion'] = {
            'decoded_ipv4_packets': int(decoded),
            'observed_windows': int(len(times)),
            'parser_audit': audit,
            'packet_limit': int(packet_limit),
        }
        return result

    def public_status(self):
        return {
            'enabled': True,
            'role': 'state_forecasting_only',
            'model_sha256': EXPECTED['model'],
            'feature_count': 34,
            'history_windows': HISTORY,
            'forecast_windows': HORIZON,
            'window_seconds': WINDOW_SECONDS,
            'packet_features_trained': True,
            'shadow_heads_enabled': self.experimental_heads is not None,
            'risk_head_trained': False,
            'stage_head_trained': False,
            'semantic_support_contract': 'V122 FROZEN',
            'fresh_external_evidence': 'V123 PASS',
            'v123_improvement_vs_persistence': self.external_result['state_forecasting']['calibrated_improvement_vs_persistence'],
            'claim_boundary': 'State forecasting only; legacy pinned risk runtime remains separate for risk/response.',
        }
