"""One fixed historical graph, actual cloud model state inference, never live risk."""
import json
import math

def run(model, checkpoint):
    from garuda_v3.data import FEATURES
    import numpy as np
    graph=json.loads((checkpoint/"replay.json").read_text())
    if graph.get("data_source")!="held_out_capture_replay":
        raise ValueError("Unexpected historical fixture")
    x,a,m,times=model.validate(graph)
    if not (x[0,:,:,FEATURES.index("packet_features_present")]*m[0]).any():
        raise ValueError("Packet evidence absent")
    mean,_,_=model.model.forward(x,a,m,model.meta["horizon"])
    pred=np.asarray(mean.data[0],dtype=float)
    if pred.shape!=(4,len(FEATURES)) or not np.isfinite(pred).all():
        raise ValueError("Invalid state inference")
    last=(x[0,-1]*m[0,-1,:,None]).sum(0)/max(float(m[0,-1].sum()),1.)
    indices=[FEATURES.index(n) for n in ("flow_count_log","bytes_log","packets_log")]
    # No raw host names, graphs, attack scores or alerts leave the backend.
    def feature_values(row):
        values=[float(row[i]) for i in indices]
        if not all(math.isfinite(v) and 0<=v<=1 for v in values):
            raise ValueError("State value outside normalized bounds")
        return [round(v,6) for v in values]
    return {"source":"fixed_historical_packet_state_inference","mode":"REPLAY_ONLY",
            "capture_cutoff":float(times[-1]+model.meta["window_seconds"]),
            "history_seconds":model.meta["history"]*model.meta["window_seconds"],
            "features":["flow_count_log","bytes_log","packets_log"],
            "last_observed":feature_values(last),
            "trajectory":[{"horizon_seconds":(i+1)*model.meta["window_seconds"],
                           "state":feature_values(row)} for i,row in enumerate(pred)],
            "live":False,"risk_validated":False,"automatic_containment":False}
