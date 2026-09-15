"""Audit existing candidate events and prevent historical graphs becoming fresh holdouts.
This exports evidence gaps; it never converts unverified event points into labels.
"""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
import numpy as np
from .data import load_dataset


def audit(graph,timeline,history=8):
    d=load_dataset(graph);doc=json.loads(Path(timeline).read_text());times=d['times'];step=d['metadata']['window_seconds']
    groups=defaultdict(list)
    for event in doc['events']:
        cutoff=float(event['epoch']);available=times[times+step<=cutoff]
        enough=len(available)>=history and np.all(np.diff(available[-history:])==step) and cutoff-(available[-1]+step)<step
        groups[event['publisher_stage']].append(dict(epoch=cutoff,source_id=event['source_id'],
            observed_history_windows=int(len(available)),has_contiguous_history=bool(enough)))
    return dict(source_sha256=d['metadata']['source_sha256'],history_windows=history,window_seconds=step,
        annotation_sha256=hashlib.sha256(Path(timeline).read_bytes()).hexdigest(),
        first_complete_window_start=int(times[0]),
        stages={stage:dict(candidate_rows=len(events),unique_event_times=len({e['epoch'] for e in events}),
            candidates_with_history=sum(e['has_contiguous_history'] for e in events),first_event=events[0]) for stage,events in groups.items()},
        labels_promoted=False,supervised_training_allowed=False,
        reasons=['Original Caldera Attack_info.csv unavailable; cannot verify host/PID/clock alignment',
                 'Candidate process first-seen time is not verified compromise time',
                 'No reviewed complete negative-stage coverage',
                 'Phase 2 was previously evaluated; cannot be called fresh holdout'])


def freeze_holdout(registry,candidate_hashes,output):
    """Reject already-used sources; freeze before fitting, not after inspecting scores."""
    known=set(registry['previously_used_source_hashes'])
    if not candidate_hashes or len(set(candidate_hashes))!=len(candidate_hashes):raise ValueError('Distinct nonempty source hashes required')
    if any(len(h)!=64 or any(c not in '0123456789abcdef' for c in h) for h in candidate_hashes):raise ValueError('Invalid SHA-256')
    if known.intersection(candidate_hashes):raise ValueError('Previously used source cannot be frozen as a fresh holdout')
    # The registry is an audit record, not independent proof of never-seen data.
    with Path(output).open('x') as f:json.dump(dict(source_hashes=candidate_hashes,status='reserved_before_fit',
        limitation='Fresh relative to recorded usage only; operator must preserve complete experiment history'),f,indent=2)


def main():
    root=Path('datasets/v11');root.mkdir(exist_ok=True)
    result=audit('datasets/multisource/graphs/cicapt_phase2.npz','datasets/multisource/phase2_candidate_timeline.json')
    (root/'timeline_readiness.json').write_text(json.dumps(result,indent=2))
    sources={}
    for parent in ('datasets/ids2018','datasets/multisource/graphs'):
        for p in Path(parent).rglob('*.npz'):
            try:d=load_dataset(p)
            except (KeyError,ValueError):continue
            h=d['metadata']['source_sha256'];sources.setdefault(h,[]).append(str(p))
    registry=dict(previously_used_source_hashes=sorted(sources),paths=sources,
        policy='Conservatively mark all previously prepared research graphs as already seen',
        independent_review_complete=False)
    (root/'source_usage_registry.json').write_text(json.dumps(registry,indent=2))
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
