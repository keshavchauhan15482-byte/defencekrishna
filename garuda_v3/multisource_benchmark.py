"""Fixed three-seed source-addition experiment; no test-driven parameter search."""
import json
import subprocess
import sys
from pathlib import Path
import numpy as np


def main():
    root=Path('datasets/multisource');out=Path('garuda_v3/artifacts/multisource')
    old=[f'datasets/ids2018/labelled/{name}.npz' for name in
         ('Thursday-22-02-2018','Friday-23-02-2018','Friday-02-03-2018')]
    values={}
    for experiment in ('ids_only','ids_plus_cicapt'):
        values[experiment]={a:[] for a in ('lstm','gnn_lstm')}
        for seed in (42,43,44):
            dest=out/f'{experiment}_seed{seed}'
            graphs=old+([str(root/'graphs/cicapt_phase1.npz')] if experiment=='ids_plus_cicapt' else [])+[str(root/'graphs/cicapt_phase2.npz')]
            if not (dest/'metrics.json').exists():
                cmd=[sys.executable,'-m','garuda_v3.train','--graphs',*graphs,'--output',str(dest),
                    '--epochs','12','--stride','16','--seed',str(seed),'--decoder','residual',
                    '--allow-unknown-labels','--calibrate','--balance-risk','--split-manifest',
                    str(root/f'{experiment}_split.json'),'--evaluation-scope','new_predeclared_holdout']
                with (root/f'{experiment}_seed{seed}.log').open('w') as log:
                    subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=True)
            report=json.loads((dest/'metrics.json').read_text())
            for architecture in values[experiment]:
                m=report['models'][architecture]
                values[experiment][architecture].append(dict(seed=seed,state_mse=m['state_mse'],
                    difference_vs_persistence=m['state_evidence']['paired_mse_difference'],
                    block_interval=m['state_evidence']['paired_block_bootstrap_95pct']))
            print(experiment,seed,'completed',flush=True)
    summary={}
    for experiment,models in values.items():
        summary[experiment]={}
        for architecture,rows in models.items():
            vals=np.array([r['state_mse'] for r in rows])
            summary[experiment][architecture]=dict(mean_mse=float(vals.mean()),seed_sd=float(vals.std(ddof=1)),runs=rows)
    result=dict(experiments=summary,persistence_mse=report['state_persistence_mse'],
        test_examples=report['split_counts'][2]['examples'],seeds=[42,43,44],
        target='Four future one-minute pooled network states',
        scope='One held-out CICAPT phase; seed variation is not independent dataset replication',
        risk_fpr_recall=None,warning_lead_time=None,supervised_stage_accuracy=None,
        reason='CICAPT network ground truth and compromise timeline unverified',
        automatic_containment_approved=False,default_model_changed=False)
    (root/'benchmark_summary.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
