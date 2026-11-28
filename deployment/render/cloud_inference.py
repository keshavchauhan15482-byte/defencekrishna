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
        self._status_cache=None
        self._status_at=0.0
        self._replay_cache=None

    def load(self):
        if self.model is None:
            from garuda_v3.inference import ForecastService
            self.model=ForecastService(CHECKPOINT)
            if self.model.meta.get("mode")!="host" or self.model.meta.get("packet_features_trained") is not True:
                self.model=None
                raise RuntimeError("Packet-trained host checkpoint required")
        return self.model

    def status(self):
        # A readiness check must not queue behind an in-flight inference.
        # Cache only metadata from an actual integrity-checked load.
        now=time.monotonic()
        if self._status_cache is not None and now-self._status_at<60:
            return dict(self._status_cache)
        base={"execution":"cloud_on_demand","packet_source":"external_authorized_graph_required",
              "automatic_containment":False,"live_prediction":False}
        if not self.lock.acquire(blocking=False):
            return dict(base,status="busy")
        try:
            try:
                model=self.load()
                result=dict(base,status="ready",
                            support_gate_configured=model.support_gate is not None,
                            history_seconds=model.meta["history"]*model.meta["window_seconds"],
                            window_seconds=model.meta["window_seconds"])
            except Exception:
                result=dict(base,status="unavailable")
            self._status_cache=result
            self._status_at=time.monotonic()
            return dict(result)
        finally:
            self.lock.release()

    def historical_state(self):
        # Compute the fixed historical sample once per worker, never accept
        # external replay inputs and never publish into the live event stream.
        if self._replay_cache is not None:
            return self._replay_cache
        if not self.lock.acquire(blocking=False):
            return None
        try:
            from deployment.render.packet_replay import run
            self._replay_cache=run(self.load(), CHECKPOINT)
            return self._replay_cache
        except Exception:
            return None
        finally:
            self.lock.release()

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
