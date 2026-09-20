"""Portable V48 fold scorer. Scores are tail evidence, NOT attack probabilities.

Artifacts preserve the research minute-state contract and must not be used on the
10-second graph checkpoint's inputs. No pickle deserialization or containment.
"""
from pathlib import Path
import hashlib
import json
import numpy as np
import torch
import sklearn
from sklearn.preprocessing import StandardScaler
from .v47_unseen_family import HISTORY, HORIZON, build_world_model, anomaly_score
from .v48_unseen_fusion import COMPONENTS, tail_evidence, fused_score


def export_fold(path, fold, config, threshold, feature_names):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=False)
    world, components = fold['world'], fold['components']
    logistic = components['runtime_logistic']
    scaler = world['runtime_scaler']
    arrays = {
        'state_median': np.asarray(world['imputer_median']),
        'state_mean': scaler.mean_, 'state_scale': scaler.scale_,
        'logistic_median': logistic['median'],
        'logistic_mean': logistic['scaler'].mean_,
        'logistic_scale': logistic['scaler'].scale_,
        'logistic_coef': logistic['model'].coef_,
        'logistic_intercept': logistic['model'].intercept_,
    }
    for key, value in world['runtime_model'].state_dict().items():
        arrays['weight.' + key] = value.cpu().numpy()
    for key, (center, scale) in components['runtime_references'].items():
        arrays[key + '_center'], arrays[key + '_scale'] = center, scale
    for key in COMPONENTS:
        arrays['cal.' + key] = components['raw'][key][components['cal_benign']]
    np.savez_compressed(path / 'arrays.npz', **arrays)
    manifest = {
        'sklearn_version': sklearn.__version__, 'torch_version': torch.__version__,
        'schema': 'garuda.v48.fold.v1', 'history': HISTORY, 'horizon': HORIZON,
        'window_seconds': 60, 'feature_names': list(feature_names),
        'seed': fold['seed'], 'held_out_family': fold['family'],
        'weights': config['weights'], 'threshold': float(threshold),
        'state_gate_passed': bool(world['state_gate_passed']),
        'automatic_containment': False, 'score_kind': 'benign_tail_evidence',
        'arrays_sha256': hashlib.sha256((path / 'arrays.npz').read_bytes()).hexdigest(),
    }
    (path / 'manifest.json').write_text(json.dumps(manifest, indent=2, allow_nan=False))
    return manifest


class V48Runtime:
    def __init__(self, path):
        path = Path(path)
        self.meta = json.loads((path / 'manifest.json').read_text())
        if self.meta['sklearn_version'] != sklearn.__version__ or self.meta['torch_version'] != torch.__version__:
            raise ValueError('V48 dependency versions differ; revalidate export parity before use')
        raw = (path / 'arrays.npz').read_bytes()
        if hashlib.sha256(raw).hexdigest() != self.meta['arrays_sha256']:
            raise ValueError('V48 artifact checksum mismatch')
        if (self.meta['schema'], self.meta['history'], self.meta['horizon'], self.meta['window_seconds']) != ('garuda.v48.fold.v1', HISTORY, HORIZON, 60):
            raise ValueError('Incompatible V48 time contract')
        with np.load(path / 'arrays.npz', allow_pickle=False) as loaded:
            self.a = {key: loaded[key].copy() for key in loaded.files}
        self.model = build_world_model(len(self.meta['feature_names']))
        self.model.load_state_dict({k[7:]: torch.from_numpy(v) for k, v in self.a.items() if k.startswith('weight.')})
        self.model.eval()

    def predict(self, X, feature_names, window_seconds=60):
        if list(feature_names) != self.meta['feature_names'] or window_seconds != 60:
            raise ValueError('V48 requires exact ordered minute-state features')
        X = np.asarray(X, dtype=np.float32)
        if X.ndim != 3 or X.shape[1:] != (HISTORY, len(feature_names)) or not len(X):
            raise ValueError('Invalid V48 history shape')
        a = self.a
        z = X.copy()
        bad = ~np.isfinite(z)
        z[bad] = a['state_median'][np.where(bad)[-1]]
        # Match sklearn float32 transform's separate in-place operations exactly.
        scaler = StandardScaler()
        scaler.mean_, scaler.scale_ = a['state_mean'], a['state_scale']
        scaler.n_features_in_ = len(feature_names)
        z = scaler.transform(z.reshape(-1, len(feature_names))).reshape(z.shape)
        with torch.no_grad():
            pred = self.model(torch.from_numpy(z)).numpy()
        persistence = np.repeat(z[:, -1:, :], HORIZON, axis=1)
        delta = pred - persistence
        flat = X.reshape(len(X), -1).astype(np.float64)
        bad = ~np.isfinite(flat)
        flat[bad] = a['logistic_median'][np.where(bad)[1]]
        flat = (flat - a['logistic_mean']) / a['logistic_scale']
        logits = (flat @ a['logistic_coef'].T + a['logistic_intercept']).reshape(-1)
        from scipy.special import expit
        raw = {
            'known_attack_transfer': expit(logits),
            'future_state_novelty': anomaly_score(pred, a['future_center'], a['future_scale']),
            'predicted_delta_novelty': anomaly_score(delta, a['delta_center'], a['delta_scale']),
            'transition_energy': np.mean(delta * delta, axis=(1, 2)),
            'history_state_novelty': anomaly_score(persistence[:, :1, :], a['history_center'], a['history_scale']),
        }
        evidence = {key: tail_evidence(a['cal.' + key], value) for key, value in raw.items()}
        score = fused_score(evidence, self.meta['weights'])
        return {'state_scaled': pred, 'score': score,
                'alert': (score >= self.meta['threshold']) & self.meta['state_gate_passed'],
                'components': evidence,
                'transfer_feature_contributions': (flat * a['logistic_coef']).reshape(len(X), HISTORY, len(feature_names)).sum(axis=1),
                'transition_feature_energy': np.mean(delta * delta, axis=1),
                'automatic_containment': False,
                'score_kind': 'benign_tail_evidence'}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--history-npz', required=True, help='X[N,8,F], feature_names[F], window_seconds scalar; no labels')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with np.load(args.history_npz, allow_pickle=False) as source:
        result = V48Runtime(args.artifact).predict(source['X'], source['feature_names'].tolist(), int(source['window_seconds']))
    payload = {k: v.tolist() if isinstance(v, np.ndarray) else {n: a.tolist() for n, a in v.items()} if isinstance(v, dict) else v for k, v in result.items()}
    with Path(args.output).open('x') as out:
        json.dump(payload, out, allow_nan=False)


if __name__ == '__main__':
    main()
