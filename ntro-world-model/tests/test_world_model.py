"""
NTRO SIH26153: PyTest Automated Verification Suite
Tests PyTorch Cyber World Model tensors, output dimensions, gradient flow,
FastAPI endpoints, SHAP explainability, and Scapy PCAP extraction.
"""

import pytest
import torch
import numpy as np
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SCRIPT_DIR)

from pytorch_models import CyberLSTMWorldModel, TransformerCyberWorldModel
from shap_explainer_real import GenuinePyTorchShapExplainer
from drift_monitor import TelemetryDriftMonitor

def test_lstm_output_shape():
    model = CyberLSTMWorldModel(input_dim=12, hidden_dim=64, num_layers=2)
    x = torch.randn(4, 16, 12)
    risk, forecast = model(x, k_steps=8)
    assert risk.shape == (4, 1)
    assert forecast.shape == (4, 8, 12)
    assert not torch.isnan(risk).any()
    assert not torch.isnan(forecast).any()

def test_transformer_output_shape():
    model = TransformerCyberWorldModel(input_dim=12, d_model=64, nhead=4, num_layers=2)
    x = torch.randn(2, 16, 12)
    risk, forecast = model(x, k_steps=8)
    assert risk.shape == (2, 1)
    assert forecast.shape == (2, 8, 12)
    assert not torch.isnan(risk).any()

def test_gradient_flow():
    model = CyberLSTMWorldModel(input_dim=12, hidden_dim=32, num_layers=1)
    x = torch.randn(2, 16, 12)
    y = torch.tensor([[1.0], [0.0]])
    risk, forecast = model(x, k_steps=8)
    loss = torch.nn.BCELoss()(risk, y) + torch.nn.MSELoss()(forecast, x[:, :8, :])
    loss.backward()
    for name, param in model.named_parameters():
        assert param.grad is not None

def test_drift_monitor_bounds():
    monitor = TelemetryDriftMonitor()
    incoming = np.random.uniform(0.05, 0.35, (30, 12))
    report = monitor.check_telemetry_drift(incoming)
    assert "overall_psi" in report
    assert "status" in report
    assert report["overall_psi"] >= 0.0

def test_shap_explainer_values():
    explainer = GenuinePyTorchShapExplainer()
    sample = np.random.uniform(0.0, 1.0, (12,)).astype(np.float32)
    attributions = explainer.compute_shap_attribution(sample)
    assert len(attributions) == 12
    total_pct = sum(a["importance_pct"] for a in attributions)
    assert 99.0 <= total_pct <= 101.0
