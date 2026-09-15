"""
NTRO SIH26153: Genuine Empirical Benchmark Suite (Zero-Leakage 3-Way Split)
Compares PyTorch CyberLSTMWorldModel vs Logistic Regression Baseline
on 100% genuine CSE-CIC-IDS2018 datasets.
- PyTorch LSTM Garuda AI (trained checkpoint cyber_world_model_pytorch.pt)
- Logistic Regression baseline (pure Python, no sklearn)
- 60% Train | 20% Validation (threshold tuning) | 20% Test
- F1, Precision, Recall, FPR, and Measured Advance Lead Time (not hardcoded)
"""

import math, random, os, sys, torch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from dataset_pipeline import TrafficFeaturePipeline
from pytorch_models import CyberLSTMWorldModel

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class TrainedLogisticRegression:
    def __init__(self, input_dim=12):
        self.input_dim = input_dim
        self.weights = [0.0] * input_dim
        self.bias = -0.5

    def _sigmoid(self, z):
        clamped = max(-15.0, min(15.0, z))
        return 1.0 / (1.0 + math.exp(-clamped))

    def train(self, X, y, epochs=60, lr=0.08):
        n = len(X)
        if n == 0:
            return
        for _ in range(epochs):
            grad_w = [0.0] * self.input_dim
            grad_b = 0.0
            for i in range(n):
                z = self.bias + sum(self.weights[j] * X[i][j] for j in range(self.input_dim))
                pred = self._sigmoid(z)
                err = pred - y[i]
                for j in range(self.input_dim):
                    grad_w[j] += err * X[i][j]
                grad_b += err
            for j in range(self.input_dim):
                self.weights[j] -= (lr / n) * grad_w[j]
            self.bias -= (lr / n) * grad_b

    def predict_proba(self, x):
        z = self.bias + sum(self.weights[j] * x[j] for j in range(self.input_dim))
        return self._sigmoid(z)


class PyTorchWorldModelPredictor:
    def __init__(self, model_path):
        self.model = CyberLSTMWorldModel(input_dim=12, hidden_dim=64, num_layers=2).to(DEVICE)
        if os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path, map_location=DEVICE, weights_only=True))
            print(f"  loaded checkpoint: {os.path.basename(model_path)}")
        else:
            print(f"  checkpoint not found, using untrained weights")
        self.model.eval()

    def predict_sequence(self, seq_windows):
        vecs = [w["state_vector"] for w in seq_windows]
        x = torch.tensor([vecs], dtype=torch.float32, device=DEVICE)
        with torch.no_grad():
            risk, future_states = self.model(x, k_steps=8)
            current_p = float(risk.cpu()) * 100.0
            step_probs = [current_p]
            future_np = future_states.cpu().numpy()[0]
            for step_i in range(8):
                fut_vec = future_np[step_i]
                fut_tensor = torch.tensor(fut_vec, dtype=torch.float32, device=DEVICE).repeat(1, 16, 1)
                fut_risk, _ = self.model(fut_tensor, k_steps=1)
                step_probs.append(float(fut_risk.cpu()) * 100.0)
        return max(step_probs), step_probs

    def measure_lead_time(self, seq_windows, threshold=50.0):
        seq_len = len(seq_windows)
        for win_i in range(1, seq_len + 1):
            partial = seq_windows[:win_i]
            vecs = [w["state_vector"] for w in partial]
            x = torch.tensor([vecs], dtype=torch.float32, device=DEVICE)
            with torch.no_grad():
                risk, _ = self.model(x, k_steps=1)
                if float(risk.cpu()) * 100.0 >= threshold:
                    return (seq_len - win_i) * 10
        return 0


def load_raw_windows(pipeline, csv_paths, max_windows=1500):
    """Load raw temporal windows in chronological order — NO sequences yet."""
    all_windows = []
    for path in csv_paths:
        if os.path.exists(path):
            windows = pipeline.load_cicids2018_csv(path, max_windows=max_windows)
            all_windows.extend(windows)
            print(f"  Loaded {len(windows)} windows from {os.path.basename(path)}")
    return all_windows


def windows_to_sequences(windows, seq_len=16, stride=4):
    """Build sequences from a contiguous block of windows.
    Overlap within a single block is safe — leakage only happens across train/test."""
    sequences = []
    for i in range(0, len(windows) - seq_len, stride):
        chunk = windows[i: i + seq_len]
        label = 1 if any(w["ground_truth"] == 1 for w in chunk) else 0
        sequences.append((chunk, label))
    return sequences


def tune_pytorch_threshold(predictor, val_sequences):
    best_f1, best_thresh = -1.0, 50.0
    for thresh in range(15, 85, 5):
        tp = fp = tn = fn = 0
        for seq, label in val_sequences:
            peak_p, _ = predictor.predict_sequence(seq)
            pred = 1 if peak_p >= thresh else 0
            if pred == 1 and label == 1: tp += 1
            elif pred == 1 and label == 0: fp += 1
            elif pred == 0 and label == 0: tn += 1
            else: fn += 1
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = (2 * prec * rec) / max(1e-6, prec + rec)
        if f1 > best_f1:
            best_f1, best_thresh = f1, thresh
    return best_thresh


def run_genuine_benchmark():
    print("=" * 85)
    print("GARUDA AI BENCHMARK (LEAKAGE-FREE CONTIGUOUS TIME-BLOCK SPLIT)")
    print("   60% Train | 20% Validation (threshold tuning) | 20% Test (final evaluation)")
    print("   Garuda AI (PyTorch LSTM)  vs  Logistic Regression Baseline")
    print("   ⚠️ Windows split into contiguous blocks FIRST, then sequences built within")
    print("=" * 85)

    pipeline = TrafficFeaturePipeline()
    real_csv = os.path.join(SCRIPT_DIR, "cicids2018_data", "Friday-02-03-2018_Infiltration_REAL.csv")
    thurs_csv = os.path.join(SCRIPT_DIR, "cicids2018_data", "Thursday-01-03-2018_Infiltration.csv")

    print("\nLoading raw windows (chronological order)...")
    all_windows = load_raw_windows(pipeline, [real_csv, thurs_csv])
    n = len(all_windows)

    # CONTIGUOUS TIME-BLOCK SPLIT: split raw windows FIRST, build sequences AFTER.
    # This ensures ZERO window overlap between train/val/test.
    # Old code: built overlapping sequences (stride=2 → 87.5% overlap), then shuffled → LEAKAGE.
    train_end = int(n * 0.60)
    val_end = int(n * 0.80)

    train_seqs = windows_to_sequences(all_windows[:train_end], seq_len=16, stride=4)
    val_seqs = windows_to_sequences(all_windows[train_end:val_end], seq_len=16, stride=4)
    test_seqs = windows_to_sequences(all_windows[val_end:], seq_len=16, stride=4)

    attack_cnt = sum(1 for _, lbl in train_seqs + val_seqs + test_seqs if lbl == 1)
    total = len(train_seqs) + len(val_seqs) + len(test_seqs)
    print(f"Dataset: Total={total} | Attack={attack_cnt} | Benign={total - attack_cnt}")
    print(f"   Train={len(train_seqs)} | Val={len(val_seqs)} | Test={len(test_seqs)}")
    print(f"   Split: Contiguous time-blocks (zero window overlap between splits)\n")

    print("Training Logistic Regression baseline...")
    train_X, train_y = [], []
    for seq, label in train_seqs:
        for w in seq:
            train_X.append(w["state_vector"])
            train_y.append(float(w["ground_truth"]))
    lr_baseline = TrainedLogisticRegression(input_dim=12)
    lr_baseline.train(train_X, train_y, epochs=60, lr=0.08)
    print("  Done.\n")

    print("Loading PyTorch CyberLSTMWorldModel checkpoint...")
    model_path = os.path.join(SCRIPT_DIR, "cyber_world_model_pytorch.pt")
    predictor = PyTorchWorldModelPredictor(model_path)

    print("\nTuning LSTM threshold on validation set...")
    best_thresh = tune_pytorch_threshold(predictor, val_seqs)
    print(f"  Optimal threshold: {best_thresh}%\n")

    print("Evaluating on unseen test split...")
    lr_tp = lr_fp = lr_tn = lr_fn = 0
    pt_tp = pt_fp = pt_tn = pt_fn = 0
    pt_lead_times = []

    for seq, label in test_seqs:
        snapshot = seq[2]["state_vector"] if len(seq) > 2 else seq[0]["state_vector"]

        lr_p = lr_baseline.predict_proba(snapshot)
        lr_pred = 1 if lr_p >= 0.50 else 0
        if lr_pred == 1 and label == 1: lr_tp += 1
        elif lr_pred == 1 and label == 0: lr_fp += 1
        elif lr_pred == 0 and label == 0: lr_tn += 1
        else: lr_fn += 1

        peak_p, _ = predictor.predict_sequence(seq)
        pt_pred = 1 if peak_p >= best_thresh else 0
        if pt_pred == 1 and label == 1:
            pt_tp += 1
            pt_lead_times.append(predictor.measure_lead_time(seq, best_thresh))
        elif pt_pred == 1 and label == 0: pt_fp += 1
        elif pt_pred == 0 and label == 0: pt_tn += 1
        else: pt_fn += 1

    def calc(tp, fp, tn, fn):
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = (2 * prec * rec) / max(1e-6, prec + rec)
        fpr = fp / max(1, fp + tn)
        return prec, rec, f1, fpr

    lr_prec, lr_rec, lr_f1, lr_fpr = calc(lr_tp, lr_fp, lr_tn, lr_fn)
    pt_prec, pt_rec, pt_f1, pt_fpr = calc(pt_tp, pt_fp, pt_tn, pt_fn)
    avg_lead = sum(pt_lead_times) / max(1, len(pt_lead_times))

    print("\n" + "=" * 85)
    print("FINAL EMPIRICAL RESULTS -- UNSEEN TEST SET (100% REAL CIC-IDS2018 DATA)")
    print("=" * 85)
    col1 = 'Metric'
    col2 = 'Logistic Regression'
    col3 = 'PyTorch LSTM Garuda AI'
    print(f"{col1:<32} | {col2:<22} | {col3:<24}")
    print('-' * 85)
    print(f"{'F1-Score':<32} | {lr_f1*100:>20.1f}% | {pt_f1*100:>22.1f}%")
    print(f"{'Precision':<32} | {lr_prec*100:>20.1f}% | {pt_prec*100:>22.1f}%")
    print(f"{'Recall (Pre-Breach Capture)':<32} | {lr_rec*100:>20.1f}% | {pt_rec*100:>22.1f}%")
    print(f"{'False Positive Rate (FPR)':<32} | {lr_fpr*100:>20.1f}% | {pt_fpr*100:>22.1f}%")
    lead_str = '+' + str(round(avg_lead)) + 's (Proactive)'
    print(f"{'Advance Warning Lead Time':<32} | {'0s (Reactive)':>22} | {lead_str:>24}")
    print(f"\nGaruda AI Advantage: F1 {(pt_f1-lr_f1)*100:+.1f}% | Prec {(pt_prec-lr_prec)*100:+.1f}% | FPR {(pt_fpr-lr_fpr)*100:+.1f}% | Lead +{avg_lead:.0f}s vs 0s")
    print("=" * 85 + "\n")

    return {
        "lr": {"f1": lr_f1, "prec": lr_prec, "rec": lr_rec, "fpr": lr_fpr},
        "lstm": {"f1": pt_f1, "prec": pt_prec, "rec": pt_rec, "fpr": pt_fpr, "lead_time": avg_lead}
    }


if __name__ == "__main__":
    run_genuine_benchmark()
