"""Controlled dataset-separated state forecasting; risk labels are never fabricated.

All settings are frozen in v10_config.json before fitting. The V9 CICAPT test phase
has already been evaluated: V10 is a reused-holdout diagnostic, not fresh evidence.
"""
import json
import hashlib
from pathlib import Path
import numpy as np
from .data import load_dataset, development_examples, FEATURES, SCHEMA
from .model import GraphWorldModel, loss
from .autograd import Adam
from .train import batch, infer, pooled
from .state_evaluation import state_evidence

ROOT=Path('datasets/v10')
CONFIG=dict(seeds=[42,43,44],architectures=['lstm','gnn_lstm'],epochs=40,
    patience=10,learning_rate=.003,history=8,horizon=4,stride=16,
    development_fraction=.7,embargo_windows=12,
    objectives=['legacy_joint','state_only'],
    selection={'legacy_joint':'mixed validation loss; epochs 1 onward',
               'state_only':'validation state MSE; includes epoch 0 persistence'},
    risk_head_trained={'legacy_joint':'only when training labels exist','state_only':False},
    test_scope='Previously evaluated CICAPT phase2 and IDS2018 DoS15; diagnostic reused holdouts',
    default_model_changed=False,automatic_containment_approved=False)


def state_objective(model, arrays):
    x,a,m,target,labels,*_=arrays
    mean,_,_=model.forward(x,a,m,target.shape[1])
    return (mean-target).power(2).mean()


def fit_one(train,valid,architecture,seed,objective):
    model=GraphWorldModel(architecture=architecture,seed=seed,decoder='residual')
    optimizer=Adam(model.parameters(),lr=CONFIG['learning_rate'])
    rng=np.random.default_rng(seed)
    best=float('inf');best_epoch=0;weights=None;curve=[]
    def score():
        if objective=='state_only':
            mu,_,_=infer(model,valid,CONFIG['horizon'])
            return float(np.mean((mu-valid[3])**2))
        return float(loss(model,*valid[:5]).data)
    if objective=='state_only':
        best=score();weights={k:p.data.copy() for k,p in model.params.items()}
        curve.append(dict(epoch=0,validation_objective=best))
    for epoch in range(1,CONFIG['epochs']+1):
        order=rng.permutation(len(train[0]));values=[]
        for start in range(0,len(order),32):
            ids=order[start:start+32];arrays=tuple(a[ids] for a in train)
            obj=state_objective(model,arrays) if objective=='state_only' else loss(model,*arrays[:5])
            obj.backward();optimizer.step();values.append(float(obj.data))
        value=score();curve.append(dict(epoch=epoch,train_objective=float(np.mean(values)),validation_objective=value))
        if value<best:
            best=value;best_epoch=epoch;weights={k:p.data.copy() for k,p in model.params.items()}
        if epoch-best_epoch>=CONFIG['patience']:break
    for k,p in model.params.items():p.data=weights[k]
    return model,dict(best_epoch=best_epoch,epochs_run=epoch,selection_value=best,curve=curve)


def main():
    ROOT.mkdir(exist_ok=True)
    cfg=ROOT/'v10_config.json'
    if cfg.exists() and json.loads(cfg.read_text())!=CONFIG:raise ValueError('Frozen config differs')
    cfg.write_text(json.dumps(CONFIG,indent=2))
    ids=[load_dataset(f'datasets/ids2018/labelled/{name}.npz') for name in
         ('Thursday-22-02-2018','Friday-23-02-2018','Friday-02-03-2018')]
    cic=load_dataset('datasets/multisource/graphs/cicapt_phase1.npz')
    tests=[load_dataset(p) for p in ('datasets/multisource/graphs/cicapt_phase2.npz',
                                  'datasets/ids2018/fresh_holdout/labelled_graph.npz')]
    results=[]
    for source,development in [('ids_only',ids),('cicapt_only',[cic]),('combined',ids+[cic])]:
        datasets=development+tests
        manifest=dict(development=[d['metadata']['campaign_id'] for d in development],
            test=[d['metadata']['campaign_id'] for d in tests],development_fraction=.7,embargo_windows=12)
        splits,bounds=development_examples(datasets,manifest,8,4,16,allow_unknown=True)
        train,valid,test=[batch(datasets,s,8,4) for s in splits]
        (ROOT/f'{source}_split.json').write_text(json.dumps(dict(manifest=manifest,boundaries=bounds,
            source_hashes=[d['metadata']['source_sha256'] for d in datasets],
            split_examples=[len(s) for s in splits]),indent=2))
        for architecture in CONFIG['architectures']:
            for objective in CONFIG['objectives']:
                for seed in CONFIG['seeds']:
                    name=f'{source}_{architecture}_{objective}_{seed}'
                    folder=Path('garuda_v3/artifacts/v10')/name;report=folder/'metrics.json'
                    if report.exists():
                        results.append(json.loads(report.read_text()));continue
                    folder.mkdir(parents=True,exist_ok=True)
                    model,selection=fit_one(train,valid,architecture,seed,objective)
                    mu,_,_=infer(model,test,4);vmu,_,_=infer(model,valid,4)
                    base=pooled(test[0],test[2])[:,-1:, :]
                    # Validation-only descriptive error bands; no Gaussian calibration claim.
                    radius=np.quantile(abs(vmu-valid[3]),.95,axis=0)
                    row=dict(name=name,source=source,architecture=architecture,objective=objective,seed=seed,
                        selection=selection,validation_mse=float(np.mean((vmu-valid[3])**2)),
                        validation_persistence_mse=float(np.mean((pooled(valid[0],valid[2])[:,-1:]-valid[3])**2)),
                        test={},risk_fpr=None,risk_recall=None,warning_lead_time=None,
                        target='future pooled traffic state; not infiltration probability',
                        evidence_scope=CONFIG['test_scope'],automatic_containment_approved=False)
                    for index,d in enumerate(tests,len(development)):
                        take=np.array([s==index for s,i in splits[2]])
                        if not take.any():raise ValueError('Empty diagnostic test source')
                        name_test=d['metadata']['campaign_id']
                        row['test'][name_test]=dict(examples=int(take.sum()),mse=float(((mu[take]-test[3][take])**2).mean()),
                            persistence_mse=float(((base[take]-test[3][take])**2).mean()),
                            evidence=state_evidence(mu[take],test[3][take],base[take],seed),
                            validation_error_band_coverage=float((abs(mu[take]-test[3][take])<=radius).mean()))
                    meta=dict(schema=SCHEMA,features=FEATURES,mode='host',max_nodes=64,window_seconds=60,
                        history=8,horizon=4,state_head_trained=True,
                        risk_head_trained=objective=='legacy_joint' and bool((train[4]>=0).any()),
                        risk_parameters_fitted=objective=='legacy_joint' and bool((train[4]>=0).any()),
                        training_objective=objective,
                        target=row['target'],risk_output_permitted=False,gaussian_uncertainty_validated=False,
                        stage_supervised=False,automatic_containment_approved=False,
                        validation_scope=CONFIG['test_scope'],training_campaigns=manifest['development'],
                        training_source_hashes=[d['metadata']['source_sha256'] for d in development],
                        selection=selection['best_epoch'],state_only_experiment=True)
                    model.save(folder/f'{architecture}.npz',meta)
                    np.savez_compressed(folder/'state_predictions.npz',mean=mu,target=test[3],persistence=base,
                        example_indices=np.asarray(splits[2]),validation_error_radius=radius)
                    row['checkpoint_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.npz')}
                    report.write_text(json.dumps(row,indent=2,allow_nan=False));results.append(row)
                    print(name,'epoch',selection['best_epoch'],[(k,round(v['mse'],6)) for k,v in row['test'].items()],flush=True)
    summary=[]
    for source in ('ids_only','cicapt_only','combined'):
        for architecture in CONFIG['architectures']:
            for objective in CONFIG['objectives']:
                rows=[r for r in results if (r['source'],r['architecture'],r['objective'])==(source,architecture,objective)]
                for test in rows[0]['test']:
                    vals=np.array([r['test'][test]['mse'] for r in rows]);base=rows[0]['test'][test]['persistence_mse']
                    summary.append(dict(source=source,architecture=architecture,objective=objective,test=test,
                        mean_mse=float(vals.mean()),seed_sd=float(vals.std(ddof=1)),persistence_mse=base,
                        improvement_vs_persistence_pct=float(100*(1-vals.mean()/base)),
                        best_epochs=[r['selection']['best_epoch'] for r in rows],
                        per_seed_intervals=[r['test'][test]['evidence']['paired_block_bootstrap_95pct'] for r in rows]))
    (ROOT/'summary.json').write_text(json.dumps(dict(config=CONFIG,rows=summary),indent=2))


if __name__=='__main__':main()
