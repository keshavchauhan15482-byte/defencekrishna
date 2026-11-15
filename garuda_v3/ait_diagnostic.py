"""Fixed three-seed development study. No final-test/zero-day certification."""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from .train_v45_core import run


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cache',required=True);p.add_argument('--output',required=True)
    a=p.parse_args(); cache,out=Path(a.cache),Path(a.output)
    if out.exists():raise ValueError('New immutable experiment directory required')
    root=Path(__file__).resolve().parents[1]
    protocol=root/'docs/release/ait_development_protocol.json'
    config=json.loads(protocol.read_text());out.mkdir(parents=True)
    graphs=[cache/(c+'-graph.npz') for c in ('fox','harrison','russellmitchell')]
    freeze=dict(protocol_sha256=hashlib.sha256(protocol.read_bytes()).hexdigest(),
                graph_sha256={g.name:hashlib.sha256(g.read_bytes()).hexdigest() for g in graphs},
                scope=config['scope'],model_results_inspected=False,automatic_containment=False)
    (out/'freeze.json').write_text(json.dumps(freeze,indent=2))
    rows=[]
    for seed in config['seeds']:
        args=SimpleNamespace(graphs=list(map(str,graphs)),split_manifest=str(protocol),output=str(out/f'seed{seed}'),
             history=8,horizon=4,stride=config['stride'],seed=seed,state_epochs=config['state_epochs'],
             risk_epochs=config['risk_epochs'],stage_epochs=0,patience=3,fpr_budget=.01,
             stage_supervision=False,evaluation_scope='development_reused_holdout')
        result=run(args)
        row=dict(seed=seed,split_counts=result['split_counts'],models={})
        for name,r in result['models'].items():
            row['models'][name]={k:r[k] for k in ('test','state_mse','state_persistence_mse','state_gate_passed','risk_head_trained','validation_alert_selection') if k in r}
        rows.append(row);print(json.dumps(row),flush=True)
    report=dict(scope=config['scope'],seeds=rows,model_weights_promoted=False,automatic_containment=False,
                five_stage_claim=False,precompromise_claim=False,
                target='Future completed-flow attack presence, NOT imminent compromise',
                raw_sources_synthetic_testbeds=True)
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False))


if __name__=='__main__':main()
