"""Experimental retraining entrypoint. Never overwrites the shipped checkpoint.
Run: python train_forecast_v2.py --csv path.csv [path2.csv] --output forecast-v2
Metrics measure future attack-labelled windows, NOT compromise lead time.
Legacy feature proxies remain; validate schema and real packet telemetry before deployment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from dataset_pipeline import TrafficFeaturePipeline
from forecast_dataset import chronological_examples
from pytorch_models import CyberLSTMWorldModel


def metrics(y, p, threshold):
    pred = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return dict(f1=float(f1_score(y, pred, zero_division=0)),
                precision=float(precision_score(y, pred, zero_division=0)),
                recall=float(recall_score(y, pred, zero_division=0)),
                fpr=float(fp / (fp + tn)) if fp + tn else None,
                confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]])


def tune(y, p):
    return max(np.linspace(.05, .95, 19), key=lambda t: metrics(y, p, t)['f1'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', nargs='+', required=True)
    parser.add_argument('--output', default='forecast-v2')
    parser.add_argument('--epochs', type=int, default=30)
    args = parser.parse_args()
    if args.epochs < 1:
        parser.error('--epochs must be positive')
    torch.manual_seed(42)
    np.random.seed(42)
    torch.set_num_threads(2)
    windows = []
    hashes = {}
    for filename in args.csv:
        path = Path(filename)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in hashes.values():
            raise ValueError('Duplicate dataset content; remove repeated copies')
        hashes[str(path)] = digest
        data = TrafficFeaturePipeline().load_cicids2018_csv(str(path), max_windows=1000000)
        for w in data:
            w['source_file'] = digest
        windows.extend(data)
    splits = chronological_examples(windows)
    tensors = []
    for split in splits:
        x = torch.tensor([s['history'] for s in split], dtype=torch.float32)
        target = torch.tensor([s['future'] for s in split], dtype=torch.float32)
        y = torch.tensor([s['label'] for s in split], dtype=torch.float32).view(-1, 1)
        if len(torch.unique(y)) < 2:
            raise ValueError('Each split needs both classes; collect more captures, do not shuffle to repair')
        tensors.append((x, target, y))
    model = CyberLSTMWorldModel()
    optimizer = torch.optim.AdamW(model.parameters(), lr=.001)
    train_x, train_future, train_y = tensors[0]
    best_loss, best_state = float('inf'), None
    for epoch in range(args.epochs):
        model.train()
        order = torch.randperm(len(train_x))
        for ids in order.split(64):
            optimizer.zero_grad()
            risk, future = model(train_x[ids], k_steps=8)
            loss = torch.nn.functional.binary_cross_entropy(risk, train_y[ids]) + torch.nn.functional.mse_loss(future, train_future[ids])
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1)
            optimizer.step()
        model.eval()
        with torch.no_grad():
            vx, vf, vy = tensors[1]
            rp, fp = model(vx, k_steps=8)
            val_loss = float(torch.nn.functional.binary_cross_entropy(rp, vy) + torch.nn.functional.mse_loss(fp, vf))
        if val_loss < best_loss:
            best_loss = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    model.eval()
    baseline = LogisticRegression(max_iter=2000, random_state=42)
    # Same information cutoff, full observed history, same future target.
    baseline.fit(train_x.flatten(1).numpy(), train_y.numpy().ravel())
    probabilities = []
    with torch.no_grad():
        for x, future, y in tensors[1:]:
            risk, forecast = model(x, k_steps=8)
            probabilities.append((risk.numpy().ravel(), baseline.predict_proba(x.flatten(1).numpy())[:, 1]))
        test_x, test_future, test_y = tensors[2]
        _, pred_future = model(test_x, k_steps=8)
        dynamics_mse = float(torch.nn.functional.mse_loss(pred_future, test_future))
        persistence_mse = float(torch.nn.functional.mse_loss(test_x[:, -1:, :].expand_as(test_future), test_future))
    yval, ytest = tensors[1][2].numpy().ravel(), tensors[2][2].numpy().ravel()
    thresholds = [float(tune(yval, p)) for p in probabilities[0]]
    report = {
        'status': 'experimental_future_window_benchmark_not_market_validation',
        'target': 'any attack-labelled window in next 8 observed contiguous 10-second windows',
        'history': 16, 'horizon': 8, 'seed': 42, 'epochs': args.epochs,
        'dataset_sha256': hashes, 'split_sizes': list(map(len, splits)),
        'checkpoint_selection': 'validation loss only',
        'thresholds': dict(zip(('lstm', 'logistic_regression'), thresholds)),
        'test': {name: metrics(ytest, probabilities[1][i], thresholds[i]) for i, name in enumerate(('lstm', 'logistic_regression'))},
        'forecast_mse': dynamics_mse, 'persistence_mse': persistence_mse,
        'measured_compromise_lead_time_seconds': None,
        'limitations': ['legacy feature proxies remain', 'no attack-stage labels', 'overlapping examples are correlated', 'flow start timestamps may precede availability of completed-flow features; use flow-end event time before claiming live lead time']
    }
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    torch.save({'state_dict': best_state, 'metadata': report}, output / 'checkpoint.pt')
    (output / 'metrics.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
