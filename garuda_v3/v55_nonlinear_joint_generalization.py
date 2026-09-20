"""V55 nonlinear joint-family generalisation experiment.

Extends V54 without selecting against Exploitation/C&C outcomes.  A nonlinear
ExtraTrees history-transfer head is trained only on the same leakage-safe development
masks.  Fusion is selected on pair-held-out, already-exposed development families with
a stricter 0.75% development FPR safety margin, then frozen before the joint reserve
regression is evaluated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier

from .v47_unseen_family import (
    FPR_BUDGET, SEEDS, binary_metrics, build_minute_state,
    choose_network_numeric_features, detect_label_hierarchy, fpr_threshold,
    make_sequences, parse_time, sha256, temporal_masks,
)
from .v48_strict_runner import canonical_family_name, reserve_exposure_mask
from .v48_unseen_fusion import EXPOSED_DEVELOPMENT_FAMILIES, fused_score, tail_evidence
from .v54_joint_family_generalization import (
    DEFAULT_RESERVE, _future_presence, _joint_development_split,
    _joint_reserve_split, _metric, _prepare_world_components,
    build_pair_holdout_cache,
)

BASE_COMPONENTS = (
    'known_attack_transfer', 'future_state_novelty', 'predicted_delta_novelty',
    'transition_energy', 'history_state_novelty'
)
COMPONENTS = BASE_COMPONENTS + ('nonlinear_temporal_transfer',)
POLICY_BUDGETS = (0.001, 0.0025, 0.005)
DEV_FPR_MARGIN = 0.0075


def temporal_history_features(X):
    X = np.asarray(X, dtype=np.float64)
    flat = X.reshape(len(X), -1)
    mean = np.nanmean(X, axis=1)
    std = np.nanstd(X, axis=1)
    last = X[:, -1, :]
    delta = X[:, -1, :] - X[:, 0, :]
    recent = X[:, -1, :] - X[:, -2, :]
    return np.concatenate([flat, mean, std, last, delta, recent], axis=1)


def nonlinear_transfer_score(X, target, split, seed):
    tr = np.where(split['train'])[0]
    if len(tr) < 50 or len(np.unique(target[tr])) < 2:
        return None
    feat = temporal_history_features(X)
    feat[~np.isfinite(feat)] = np.nan
    med = np.nanmedian(feat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = med[np.where(bad)[1]]
    model = ExtraTreesClassifier(
        n_estimators=240,
        max_features='sqrt',
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=seed,
        n_jobs=1,
    )
    model.fit(feat[tr], np.asarray(target)[tr])
    return model.predict_proba(feat)[:, 1]


def extended_evidence(base_components, sequences, split, seed):
    evidence = dict(base_components['evidence'])
    raw = nonlinear_transfer_score(sequences['X'], sequences['y'], split, seed)
    if raw is None:
        raise RuntimeError('Nonlinear transfer head lacks two-class development support')
    cal_benign = base_components['cal_benign']
    evidence['nonlinear_temporal_transfer'] = tail_evidence(raw[cal_benign], raw)
    return evidence


def fused_extended(evidence, weights):
    score = np.zeros_like(next(iter(evidence.values())), dtype=float)
    for name in COMPONENTS:
        score += float(weights.get(name, 0.0)) * evidence[name]
    return score


def candidate_weights():
    # Coarse simplex is intentionally fixed before reserve evaluation.
    rows, seen = [], set()
    n = 4
    def comps(total, parts, prefix=()):
        if parts == 1:
            yield prefix + (total,); return
        for i in range(total + 1):
            yield from comps(total-i, parts-1, prefix+(i,))
    for counts in comps(n, len(COMPONENTS)):
        vals = tuple(x/n for x in counts)
        if vals in seen: continue
        seen.add(vals)
        rows.append({
            'name': '_'.join(f'{COMPONENTS[i]}{int(v*100)}' for i,v in enumerate(vals) if v),
            'weights': {c: float(v) for c,v in zip(COMPONENTS, vals)},
        })
    return rows


def robust_objective(rows):
    state = [r for r in rows if r['state_gate_passed']]
    safe = [r for r in state if r['fpr'] is not None and r['fpr'] <= DEV_FPR_MARGIN]
    gate = [r for r in safe if r['recall'] is not None and r['recall'] >= .80]
    recalls = [float(r['recall']) for r in safe if r['recall'] is not None]
    worst = min(recalls) if recalls else 0.0
    mean = float(np.mean(recalls)) if recalls else 0.0
    # Prefer lower policy budget at exact ties to leave calibration headroom.
    return (len(gate), len(safe), worst, mean)


def choose_fusion(dev_cache, sequences, time_masks, reserve_mask):
    ext_by_key = {}
    rows_ext = []
    for row in dev_cache:
        key = (tuple(row['withheld_pair']), int(row['seed']))
        if key not in ext_by_key:
            split = _joint_development_split(sequences, time_masks, key[0], reserve_mask)
            ext_by_key[key] = extended_evidence(row['components'], sequences, split, row['seed'])
        copy = dict(row)
        copy['evidence_ext'] = ext_by_key[key]
        rows_ext.append(copy)

    candidates = []
    for cand in candidate_weights():
        for budget in POLICY_BUDGETS:
            folds = []
            for row in rows_ext:
                score = fused_extended(row['evidence_ext'], cand['weights'])
                policy = row['components']['policy_benign']
                threshold = fpr_threshold(score[policy], budget)
                m = _metric(row['positive'], row['negative'], score, threshold)
                if m is None: continue
                folds.append({
                    'withheld_pair': list(row['withheld_pair']), 'family': row['family'],
                    'seed': row['seed'], 'state_gate_passed': bool(row['world']['state_gate_passed']),
                    'recall': m.get('recall'), 'fpr': m.get('fpr'), 'threshold': float(threshold),
                })
            obj = robust_objective(folds)
            candidates.append({'name': cand['name'], 'weights': cand['weights'],
                               'policy_budget': float(budget), 'objective': list(obj), 'folds': folds})
    candidates.sort(key=lambda c: tuple(c['objective']) + (-c['policy_budget'],), reverse=True)
    return candidates[0], candidates


def evaluate_joint(sequences, time_masks, reserve, seeds, epochs, frozen):
    split = _joint_reserve_split(sequences, time_masks, reserve)
    positive = {f:_future_presence(sequences,f) for f in reserve}
    out = {f:{} for f in reserve}
    component_refs = {f:{c:[] for c in COMPONENTS} for f in reserve}
    for seed in seeds:
        print(f'V55 JOINT seed={seed}', flush=True)
        world, base = _prepare_world_components(sequences, split, seed, epochs)
        ev = extended_evidence(base, sequences, split, seed)
        score = fused_extended(ev, frozen['weights'])
        policy = base['policy_benign']
        threshold = fpr_threshold(score[policy], frozen['policy_budget'])
        for fam in reserve:
            m = _metric(positive[fam], split['test_negative'], score, threshold)
            state_mask = positive[fam] | split['test_negative']
            mse = float(np.mean((world['pred'][state_mask]-world['future_scaled'][state_mask])**2))
            pmse = float(np.mean((world['persistence'][state_mask]-world['future_scaled'][state_mask])**2))
            out[fam][str(seed)] = {
                'threshold':float(threshold),'test':m,
                'state_gate_passed':bool(world['state_gate_passed']),
                'test_state_mse':mse,'test_persistence_mse':pmse,
                'test_state_gate_passed':bool(mse<pmse),
            }
            for c in COMPONENTS:
                ct = fpr_threshold(ev[c][policy], frozen['policy_budget'])
                cm = _metric(positive[fam], split['test_negative'], ev[c], ct)
                component_refs[fam][c].append({'seed':seed,'threshold':float(ct),'test':cm})
    def summary(rows):
        vals=list(rows.values())
        def st(k):
            x=[r['test'].get(k) for r in vals if r['test'].get(k) is not None]
            return {'mean':float(np.mean(x)) if x else None,
                    'sd':float(np.std(x,ddof=1)) if len(x)>1 else None}
        return {'evaluated_seeds':len(vals),'recall':st('recall'),'fpr':st('fpr'),
                'precision':st('precision'),'f1':st('f1'),
                'state_gate_passed_all_seeds':all(r['state_gate_passed'] for r in vals),
                'test_state_gate_passed_all_seeds':all(r['test_state_gate_passed'] for r in vals),
                'reference_gate_passed_all_seeds':all(r['state_gate_passed'] and r['test']['fpr']<=FPR_BUDGET and r['test']['recall']>=.80 for r in vals)}
    return {'support':{'train':int(split['train'].sum()),'calibration':int(split['calibration'].sum()),
                       'policy':int(split['policy'].sum()),'negative':int(split['test_negative'].sum()),
                       'positive':{f:int(positive[f].sum()) for f in reserve}},
            'families':{f:{'seeds':out[f],'summary':summary(out[f]),'component_reference':component_refs[f]} for f in reserve}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv',required=True); p.add_argument('--output',required=True)
    p.add_argument('--epochs',type=int,default=12); p.add_argument('--seeds',nargs='+',type=int,default=list(SEEDS))
    p.add_argument('--reserve-families',nargs='+',default=list(DEFAULT_RESERVE)); args=p.parse_args()
    if len(set(args.seeds))<3: p.error('At least three distinct seeds required')
    out=Path(args.output)
    if out.exists(): p.error('Output exists; V55 evidence is immutable')
    out.mkdir(parents=True)
    csv=Path(args.csv); df=pd.read_csv(csv,low_memory=False)
    dt,date_col,ts_col,time_method=parse_time(df)
    binary,family,binary_col,family_col,profiles=detect_label_hierarchy(df)
    family=family.map(canonical_family_name)
    feature_cols,feature_audit=choose_network_numeric_features(df)
    state,names,src_col=build_minute_state(df,dt,binary,family,feature_cols)
    seq=make_sequences(state,names); masks,boundaries=temporal_masks(seq['cutoff'])
    available=sorted({x for steps in seq['step_families'] for fams in steps for x in fams})
    reserve=[canonical_family_name(x) for x in args.reserve_families]
    if any(x not in available for x in reserve): raise RuntimeError(f'Reserve missing; available={available}')
    exposed=[canonical_family_name(x) for x in EXPOSED_DEVELOPMENT_FAMILIES if canonical_family_name(x) in available and canonical_family_name(x) not in reserve]
    dev,pair_support,reserve_mask=build_pair_holdout_cache(seq,masks,exposed,reserve,tuple(args.seeds),args.epochs)
    winner,candidates=choose_fusion(dev,seq,masks,reserve_mask)
    frozen={'protocol':'V55 nonlinear pair-held-out development-selected fusion',
            'weights':winner['weights'],'policy_budget':winner['policy_budget'],
            'selection_candidate':winner['name'],'selection_objective':winner['objective'],
            'development_fpr_margin':DEV_FPR_MARGIN,'development_families':exposed,
            'reserve_families':reserve,'reserve_metrics_used_for_selection':False,
            'reserve_blocked_during_selection':True}
    (out/'frozen_config.json').write_text(json.dumps(frozen,indent=2)+'\n')
    joint=evaluate_joint(seq,masks,reserve,tuple(args.seeds),args.epochs,frozen)
    report={'protocol':frozen['protocol'],'claim_boundary':'Regression on previously exposed Exploitation/C&C; no fresh-holdout claim.',
            'source_sha256':sha256(csv),'seeds':list(args.seeds),'frozen_config':frozen,
            'development_pair_support':pair_support,'candidate_count':len(candidates),
            'top_candidates':[{k:c[k] for k in ('name','weights','policy_budget','objective')} for c in candidates[:20]],
            'joint_reserve_regression':joint,'automatic_containment_approved':False,
            'time':{'date_column':date_col,'timestamp_column':ts_col,'method':time_method,'boundaries':boundaries},
            'labels':{'binary':binary_col,'family':family_col,'profiles':profiles},
            'network_only_feature_audit':{'raw_selected':feature_cols,'audit':feature_audit},'source_group_column':src_col}
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'frozen_config':frozen,'joint':{f:v['summary'] for f,v in joint['families'].items()}},indent=2),flush=True)

if __name__=='__main__': main()
