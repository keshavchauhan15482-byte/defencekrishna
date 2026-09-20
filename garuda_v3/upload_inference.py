"""Bounded offline file inference using the explicitly selected runtime checkpoint."""
import hashlib
import tempfile
from pathlib import Path
import numpy as np
from .data import convert
from .pcap import convert_pcap
from .inference import ForecastService

MAX_BYTES = 8 * 1024 * 1024

def analyze(raw, kind, artifacts):
    if kind not in ("csv", "pcap") or not raw or len(raw) > MAX_BYTES:
        raise ValueError("Upload must be a CSV or PCAP file of 1 byte to 8 MiB")
    service = ForecastService(artifacts)
    meta = service.meta
    with tempfile.TemporaryDirectory(prefix="garuda-upload-") as folder:
        path = Path(folder) / ("capture." + kind)
        path.write_bytes(raw)
        kwargs = dict(mode=meta["mode"], window_seconds=meta["window_seconds"], max_nodes=meta["max_nodes"])
        data = convert(path, **kwargs) if kind == "csv" else convert_pcap(path, max_packets=250000, **kwargs)
    h = meta["history"]
    windows = len(data["times"])
    forecasts, withheld = [], []
    candidates = list(range(h, windows + 1))[-32:]
    for end in candidates:
        start = end-h
        if np.any(np.diff(data["times"][start:end]) != meta["window_seconds"]):
            withheld.append(dict(end_window=end, reason="Non-contiguous history"))
            continue
        payload = dict(schema=data["metadata"]["schema"], mode=meta["mode"],
                       window_seconds=meta["window_seconds"], data_source="uploaded_"+kind,
                       times=data["times"][start:end].tolist(),
                       node_names=data["metadata"]["node_names"][end-1])
        payload.update({k:data[k][start:end].tolist() for k in ("x","adj","mask")})
        try:
            forecasts.append(service.predict(payload))
        except ValueError as exc:
            withheld.append(dict(end_window=end, reason=str(exc)))
    return dict(status="forecast_available" if forecasts else "insufficient_evidence",
                input_sha256=hashlib.sha256(raw).hexdigest(), windows=windows,
                required_history=h, evaluated_histories=len(candidates),
                scope="Last 32 history endpoints at most; earlier file histories not evaluated",
                model_sha256=service.model_hash, model_contract=meta,
                forecasts=forecasts, withheld=withheld, automatic_containment=False,
                v48_benchmark_model=False)
