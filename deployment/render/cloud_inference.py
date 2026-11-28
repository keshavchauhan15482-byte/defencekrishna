"""Free-tier on-demand inference on private, completed observed graph exports.
No traffic capture, replay, generated telemetry, or automatic enforcement.
"""
from pathlib import Path
import re
import time
import threading
import math

MAX_GRAPH_BYTES=512*1024
CHECKPOINT=Path(__file__).resolve().parents[2]/"garuda_v3/artifacts/calibrated_host_v6"

class CloudInference:
    def __init__(self, clock=time.time):
        self.clock=clock
        self.model=None
        self.lock=threading.Lock()

    def load(self):
        if self.model is None:
            from garuda_v3.inference import ForecastService
            self.model=ForecastService(CHECKPOINT)
            if self.model.meta.get("mode")!="host" or self.model.meta.get("packet_features_trained") is not True:
                self.model=None
                raise RuntimeError("Packet-trained host checkpoint required")
        return self.model

    def status(self):
        with self.lock:
            try:
                model=self.load()
                return {"status":"ready","execution":"cloud_on_demand","packet_source":"external_authorized_graph_required",
                        "support_gate_configured":model.support_gate is not None,
                        "history_seconds":model.meta["history"]*model.meta["window_seconds"],
                        "automatic_containment":False,"live_prediction":False}
            except Exception:
                return {"status":"unavailable","execution":"cloud_on_demand","packet_source":"external_authorized_graph_required",
                        "automatic_containment":False,"live_prediction":False}

    def predict(self, data):
        if not isinstance(data,dict) or set(data)!={"schema","capture_sha256","graph"} or data["schema"]!="garuda-cloud-observed-v1":
            raise ValueError("Observed graph envelope required")
        digest=data["capture_sha256"]
        if not isinstance(digest,str) or not re.fullmatch(r"[a-f0-9]{64}",digest):
            raise ValueError("Capture provenance required")
        graph=data["graph"]
        if not isinstance(graph,dict) or set(graph)!={"schema","mode","window_seconds","times","x","adj","mask"}:
            raise ValueError("Only graph features and timestamps accepted")
        if not self.lock.acquire(blocking=False):
            raise RuntimeError("Inference busy")
        try:
            model=self.load()
            times=graph["times"]
            if not isinstance(times,list) or len(times)!=model.meta["history"] or any(type(t) not in (int,float) or not math.isfinite(t) for t in times):
                raise ValueError("Invalid graph timestamps")
            cutoff=times[-1]+model.meta["window_seconds"]
            now=self.clock()
            if not 0<=now-cutoff<=min(120,model.meta["window_seconds"]*4):
                raise ValueError("Graph is stale or not closed")
            from garuda_v3.data import FEATURES
            x,_,m,_=model.validate(graph)
            if not (x[0,:,:,FEATURES.index("packet_features_present")]*m[0]).any():
                raise ValueError("Packet evidence missing")
            result=model.predict(graph,explain=False,allow_unsupported_advisory=True)
            if result["runtime_support"]["supported"] is not True:
                return {"status":"withheld","reason":"runtime_support_unverified","execution":"cloud_on_demand","automatic_containment":False}
            # Result metadata only; input graph is never persisted or returned.
            return {"status":"forecast","execution":"cloud_on_demand","capture_sha256":digest,
                    "model_sha256":model.model_hash,"cutoff_epoch_seconds":result["cutoff_epoch_seconds"],
                    "trajectory":[{"horizon_seconds":p["horizon_seconds"],"malicious_flow_probability":p["malicious_flow_probability"]} for p in result["trajectory"]],
                    "alert":result["alert"],"supported":True,"automatic_containment":False}
        finally:
            self.lock.release()
