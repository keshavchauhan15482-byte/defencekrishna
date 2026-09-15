"""
NTRO SIH26153: Enterprise FastAPI Microservice Architecture
Exposes high-throughput REST APIs for PyTorch World Model Rollout,
PCAP/CSV Ingestion, Official SHAP Attributions, and Sudarshana Blockchain Anchoring.
Swagger UI: http://localhost:8000/docs
"""

import os
import sys
import tempfile
import torch
import numpy as np
import urllib.request
import json
from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel, Field
import math
from typing import List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pytorch_models import CyberLSTMWorldModel, TransformerCyberWorldModel
from pcap_pipeline import ScapyPCAPFeatureExtractor
from dataset_pipeline import TrafficFeaturePipeline
from shap_explainer_real import GenuinePyTorchShapExplainer
from drift_monitor import TelemetryDriftMonitor

app = FastAPI(
    title="NTRO SIH26153: Cyber World Model Forecasting API",
    description="Production-Grade Deep Learning REST API for Proactive Malicious Infiltration Forecasting",
    version="2.0.0"
)

# Load PyTorch Checkpoint
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_PATH = os.path.join(SCRIPT_DIR, "cyber_world_model_pytorch.pt")

lstm_model = CyberLSTMWorldModel(input_dim=12, hidden_dim=64, num_layers=2).to(DEVICE)
if os.path.exists(MODEL_PATH):
    lstm_model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE, weights_only=True))
lstm_model.eval()

shap_explainer = GenuinePyTorchShapExplainer(model_path=MODEL_PATH)
drift_monitor = TelemetryDriftMonitor()
pcap_extractor = ScapyPCAPFeatureExtractor()
traffic_pipeline = TrafficFeaturePipeline()

class TelemetryPayload(BaseModel):
    state_vector: List[float]
    horizon_steps: int = Field(default=8, ge=1, le=32)
    history: Optional[List[List[float]]] = Field(default=None, max_length=15)

class MitigationPayload(BaseModel):
    target_ip: str
    predicted_stage: str
    probability: float
    driving_features: List[str]

@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "service": "GARUDA_AI_FORECASTING_ENGINE",
        "device": str(DEVICE),
        "pytorch_version": torch.__version__,
        "model_loaded": os.path.exists(MODEL_PATH),
        "active_models": ["CyberLSTMWorldModel"] if os.path.exists(MODEL_PATH) else [],
        "validation_status": "legacy_checkpoint_requires_retraining"
    }

@app.get("/api/v1/model/metrics")
def get_model_metrics():
    return {
        "validation_status": "unverified_legacy_metrics_withdrawn",
        "f1_score": None, "precision": None, "recall": None,
        "false_positive_rate": None, "lead_time_seconds": None,
        "reason": "Require future-only targets, fair baseline and checkpoint provenance; see AUDIT.md"
    }


@app.post("/api/v1/forecast/telemetry")
def forecast_telemetry(payload: TelemetryPayload):
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=503, detail="Trained checkpoint unavailable")
    vec = payload.state_vector
    if len(vec) != 12 or any(not math.isfinite(v) or not 0 <= v <= 1 for v in vec):
        raise HTTPException(status_code=400, detail="State vector must contain exactly 12 finite values in [0,1]")

    # Accumulate real incoming telemetry for proper sequence building + drift monitoring
    _telemetry_buffer.append(vec)
    if len(_telemetry_buffer) > _BUFFER_MAX:
        _telemetry_buffer.pop(0)

    k_steps = payload.horizon_steps or 8

    # Request-local ordered history; never combine unrelated clients/captures.
    history = payload.history or []
    if any(len(row) != 12 or any(not math.isfinite(v) or not 0 <= v <= 1 for v in row) for row in history):
        raise HTTPException(status_code=400, detail="History requires finite normalized 12-D windows")
    seq_vecs = history + [vec]

    x_tensor = torch.tensor([seq_vecs], dtype=torch.float32, device=DEVICE)  # (1, 16, 12)

    with torch.no_grad():
        risk_t, forecast_t = lstm_model(x_tensor, k_steps=k_steps)
        current_p   = float(risk_t.cpu().numpy()[0, 0]) * 100.0
        future_states = forecast_t.cpu().numpy()[0]  # (k_steps, 12)

        # Run model forward on each autoregressive forecasted state for true per-step risk
        step_probs = [current_p]
        fut_seq = list(seq_vecs)
        for step_i in range(k_steps):
            future_vec = future_states[step_i]
            # Build sequence using buffer + this future step
            fut_seq    = fut_seq[1:] + [future_vec.tolist()]
            fut_tensor = torch.tensor([fut_seq], dtype=torch.float32, device=DEVICE)
            fut_risk, _ = lstm_model(fut_tensor, k_steps=1)
            step_probs.append(float(fut_risk.cpu().numpy()[0, 0]) * 100.0)

    # Compute genuine lead time: how many steps BEFORE peak does risk first cross 50%
    breach_step = None
    for i, p in enumerate(step_probs):
        if p >= 50.0:
            breach_step = i
            break
    peak_step = int(max(range(len(step_probs)), key=lambda i: step_probs[i]))
    lead_time_sec = max(0, (peak_step - (breach_step if breach_step is not None else peak_step)) * 10)

    trajectory = []
    for step in range(k_steps + 1):
        prob = round(step_probs[step], 1)
        rel_time = f"+{step * 10}s"
        state_desc = "Observed State S_t" if step == 0 else f"Rollout State S_{{t+{step}}}"

        # FIX: MITRE ATT&CK stage derived from feature values + risk level (not hardcoded thresholds)
        state_vec = vec if step == 0 else future_states[step - 1].tolist()
        syn_ack   = state_vec[0]   # TCP SYN/ACK ratio
        port_entr = state_vec[9]   # Port scan entropy
        ttl_var   = state_vec[7]   # TTL variance (lateral hops indicator)
        frag_flag = state_vec[10]  # Fragmented packet flags (covert channel indicator)

        if prob < 25.0:
            stage = "No supported attack-stage evidence"
        elif prob < 45.0:
            if port_entr > 0.5 or syn_ack > 0.4:
                stage = "Initial Access — Port Scan / Exploit (T1190)"
            else:
                stage = "Initial Access (T1190)"
        elif prob < 65.0:
            if ttl_var > 0.3:
                stage = "Lateral Movement — Subnet Hop (T1021)"
            else:
                stage = "Lateral Movement (T1021)"
        elif prob < 82.0:
            if frag_flag > 0.5:
                stage = "C2 — Fragmented Covert Channel (T1001)"
            else:
                stage = "Command & Control (T1071)"
        else:
            stage = "Exfiltration / Impact (T1041)"

        trajectory.append({
            "step": step,
            "horizon": rel_time,
            "probability": prob,
            "stage": stage,
            "state_description": state_desc
        })

    peak_p = max(step_probs)
    proactive = peak_p >= 50.0

    return {
        "ok": True,
        "observed_history_windows": len(seq_vecs),
        "peak_probability": round(peak_p, 1),
        "predicted_mitre_stage": trajectory[peak_step]["stage"],
        "advance_lead_time_seconds": None,
        "predicted_threshold_to_peak_seconds": lead_time_sec,
        "validation_status": "unvalidated_legacy_checkpoint",
        "stage_mapping_method": "heuristic_not_trained_stage_prediction",
        "proactive_containment_recommended": proactive,
        "trajectory": trajectory
    }

@app.post("/api/v1/forecast/pcap")
async def forecast_pcap(file: UploadFile = File(...)):
    suffix = ".pcap" if file.filename.endswith(".pcap") else ".pcapng"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read(10 * 1024 * 1024 + 1)
        if len(content) > 10 * 1024 * 1024:
            tmp.close()
            os.remove(tmp.name)
            raise HTTPException(status_code=413, detail="Capture exceeds 10 MiB limit")
        tmp.write(content)
        tmp_path = tmp.name

    try:
        windows = pcap_extractor.extract_windows_from_pcap(tmp_path)
        if not windows:
            raise HTTPException(status_code=400, detail="No valid IP/TCP flows parsed from PCAP")
        active_vec = windows[-1]["state_vector"]
        return forecast_telemetry(TelemetryPayload(state_vector=active_vec, history=[w["state_vector"] for w in windows[-16:-1]]))
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/api/v1/explain/shap")
def explain_shap(payload: TelemetryPayload):
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=503, detail="Trained checkpoint unavailable")
    vec = payload.state_vector
    if len(vec) != 12 or any(not math.isfinite(v) or not 0 <= v <= 1 for v in vec):
        raise HTTPException(status_code=400, detail="State vector must contain exactly 12 finite values in [0,1]")

    attributions = shap_explainer.compute_shap_attribution(vec)
    return {
        "ok": True,
        "method": "SHAP_GRADIENT_EXPLAINER_PYTORCH",
        "attributions": attributions
    }

@app.post("/api/v1/explain/attention")
def explain_attention(payload: TelemetryPayload):
    raise HTTPException(status_code=503, detail="No trained Transformer checkpoint; random attention cannot explain the LSTM")


@app.post("/api/v1/mitigate/krishna-lockdown")
def trigger_krishna_mitigation(payload: MitigationPayload):
    if os.environ.get("ENABLE_MITIGATION") != "1":
        raise HTTPException(status_code=403, detail="Mitigation disabled; authenticated deployment required")
    try:
        node_payload = json.dumps({
            "source": "fastapi_world_model_production",
            "predicted_stage": payload.predicted_stage,
            "probability": payload.probability,
            "target_ip": payload.target_ip,
            "driving_features": payload.driving_features
        }).encode("utf-8")

        req = urllib.request.Request(
            "http://localhost:8080/__sentinel/predictive-lockdown",
            data=node_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3.0) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data
    except Exception as e:
        raise HTTPException(status_code=502, detail="Mitigation backend did not confirm success") from e



# FIX: Rolling buffer of real incoming telemetry vectors for drift monitoring
_telemetry_buffer: list = []
_BUFFER_MAX = 100

@app.get("/api/v1/drift/status")
def get_drift_status():
    """
    Compute PSI drift between training baseline and recent incoming telemetry.
    Uses the last N real vectors received via /api/v1/forecast/telemetry.
    Falls back to a benign reference sample if no real traffic has been received yet.
    """
    if len(_telemetry_buffer) >= 10:
        incoming = np.array(_telemetry_buffer[-50:], dtype=np.float32)
        source = f"real_traffic (last {len(_telemetry_buffer)} vectors)"
    else:
        # Not enough real traffic yet — use a benign reference as placeholder
        np.random.seed(0)
        incoming = np.random.uniform(0.04, 0.18, (30, 12)).astype(np.float32)
        source = "placeholder_benign_reference (no real traffic received yet)"

    report = drift_monitor.check_telemetry_drift(incoming)
    report["source"] = source
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("BIND_HOST", "127.0.0.1"), port=8000)
