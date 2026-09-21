"""V93 active-node scaling benchmark for the pinned Garuda graph runtime.

This is a COMPUTE/SCHEMA stress test, not an accuracy benchmark. Starting from a real,
validated recorded replay, inactive graph slots are activated with deterministic clones
of observed node-state histories. Cloned nodes are intentionally disconnected, so no new
traffic semantics or attack labels are invented. The benchmark answers whether the live
checkpoint accepts 8/12/16/24/32 active-node payloads and measures inference latency.
"""
from __future__ import annotations

import argparse
import json
import platform
import resource
import time
from copy import deepcopy
from pathlib import Path

import numpy as np

from .bundle_manifest import bundle_public_metadata, resolve_active_bundle
from .inference import ForecastService

TARGET_COUNTS = (4, 8, 12, 16, 24, 32)


def expanded_payload(source: dict, count: int, max_nodes: int) -> dict:
    if count < 1 or count > max_nodes:
        raise ValueError(f"active node count {count} outside 1..{max_nodes}")
    p = deepcopy(source)
    x = np.asarray(p['x'], dtype=np.float32)
    a = np.asarray(p['adj'], dtype=np.float32)
    m = np.asarray(p['mask'], dtype=np.float32)
    if x.shape[1] != max_nodes:
        raise ValueError('source payload max_nodes mismatch')
    observed = np.where(m[-1] == 1)[0]
    if len(observed) == 0:
        raise ValueError('source payload has no observed nodes')

    # Clear every slot then rebuild exactly `count` active nodes. For existing observed
    # slots, keep their full recorded history; for additional slots, clone one recorded
    # node history. Adjacency among original nodes is retained only when both endpoints
    # remain active. Clones are disconnected by construction.
    new_x = np.zeros_like(x); new_a = np.zeros_like(a); new_m = np.zeros_like(m)
    keep = observed[:min(len(observed), count)]
    for j, old in enumerate(keep):
        new_x[:, j, :] = x[:, old, :]
        new_m[:, j] = m[:, old]
    for u, old_u in enumerate(keep):
        for v, old_v in enumerate(keep):
            new_a[:, u, v] = a[:, old_u, old_v]

    template = int(observed[0])
    for j in range(len(keep), count):
        new_x[:, j, :] = x[:, template, :]
        new_m[:, j] = 1.0
    p['x'] = new_x.tolist(); p['adj'] = new_a.tolist(); p['mask'] = new_m.tolist()
    names = list(source.get('node_names', []))
    out_names = []
    for j in range(count):
        if j < len(keep) and int(keep[j]) < len(names):
            out_names.append(names[int(keep[j])])
        else:
            out_names.append(f'synthetic-load-node-{j+1:02d}')
    p['node_names'] = out_names + [f'masked:{j}' for j in range(count, max_nodes)]
    p['data_source'] = f'synthetic_topology_scaling_from_recorded_state:{count}_active_nodes'
    return p


def bench(service, payload, repeats, explain):
    for _ in range(10 if not explain else 3):
        service.predict(payload, explain=explain)
    dt=[]
    for _ in range(repeats):
        t=time.perf_counter(); service.predict(payload, explain=explain); dt.append(time.perf_counter()-t)
    a=np.asarray(dt)*1000.0
    return {
        'n': int(len(a)), 'mean_ms': float(a.mean()),
        'p50_ms': float(np.percentile(a,50)), 'p95_ms': float(np.percentile(a,95)),
        'p99_ms': float(np.percentile(a,99)),
        'single_thread_throughput_per_second_from_mean': float(1000.0/a.mean()),
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',required=True)
    ap.add_argument('--forecast-repeats',type=int,default=120)
    ap.add_argument('--explain-repeats',type=int,default=30)
    args=ap.parse_args()
    out=Path(args.output)
    if out.exists():
        ap.error('Output exists; V93 evidence is immutable')
    out.mkdir(parents=True)

    root=Path('.').resolve(); folder=resolve_active_bundle(root)
    service=ForecastService(folder)
    source=json.loads((folder/'replay.json').read_text())
    service.validate(source)
    max_nodes=int(service.meta['max_nodes'])
    counts=[c for c in TARGET_COUNTS if c<=max_nodes]
    rows=[]
    for count in counts:
        payload=expanded_payload(source,count,max_nodes)
        service.validate(payload)
        pred=service.predict(payload,explain=False)
        row={
            'active_nodes':count,
            'validated':True,
            'forecast_horizon_steps':len(pred['trajectory']),
            'forecast_only':bench(service,payload,args.forecast_repeats,False),
            'with_gradient_x_input_explanation':bench(service,payload,args.explain_repeats,True),
        }
        rows.append(row); print(json.dumps(row,indent=2),flush=True)

    report={
        'protocol':'V93 synthetic active-node scaling stress test of pinned live runtime',
        'claim_boundary':(
            'Node expansion uses deterministic clones of recorded network-state histories solely to exercise graph runtime capacity. '
            'It does not create new attack evidence, does not measure detection accuracy, and is not a customer production load test.'
        ),
        'runtime_bundle':bundle_public_metadata(root),
        'checkpoint_sha256':service.model_hash,
        'max_nodes':max_nodes,
        'source_replay':'replay.json',
        'source_replay_is_recorded':True,
        'expanded_nodes_are_synthetic_for_load_only':True,
        'synthetic_clones_are_disconnected':True,
        'environment':{'python':platform.python_version(),'platform':platform.platform()},
        'rows':rows,
        'max_process_rss_mib':float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)/1024.0,
        'measurement_contract':{
            'in_process':True,'http_overhead_included':False,'single_threaded':True,'warmup_used':True,
            'fixed_tensor_max_nodes_means_latency_may_not_scale_linearly_with_active_mask_count':True,
        },
    }
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')


if __name__=='__main__':
    main()
