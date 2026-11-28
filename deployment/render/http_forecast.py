"""Experimental forecast of recorded page-load counts, not network attacks.
A fixed EWMA is compared with a one-step persistence baseline on chronological
closed buckets. The risk-index projection is conditional on no further denials.
No model probability, packet-feature substitution or autonomous action.
"""
import math
from .observed_index import observed_index

HORIZONS=(60,120,180,300)

def ewma(values):
    level=float(values[0])
    for v in values[1:]:
        level=.25*v+.75*level
    return level

def forecast(now, first_observed, page_buckets, denial_buckets):
    closed=int(now//60)*60
    if first_observed is None:
        return None
    # First partial minute is excluded; each later zero is zero recorded rows,
    # not evidence of complete ingress monitoring or absence of attacks.
    start=max(closed-3600,(int(first_observed//60)+1)*60)
    if closed-start<12*60:
        return None
    counts={int(t):int(n) for t,n in page_buckets}
    history=[counts.get(t,0) for t in range(start,closed,60)]
    if any(n<0 for n in history):
        return None
    # Fixed method, no hyperparameter selection on the chronological audit.
    errors=[]; baseline=[]
    for i in range(8,len(history)):
        errors.append(abs(ewma(history[:i])-history[i]))
        baseline.append(abs(history[i-1]-history[i]))
    mae=sum(errors)/len(errors)
    base_mae=sum(baseline)/len(baseline)
    # Prefer simpler persistence when EWMA does not improve the limited audit.
    use_ewma=mae<base_mae
    rate=ewma(history) if use_ewma else float(history[-1])
    points=[]
    for h in HORIZONS:
        end=now+h
        boundary=int(end//60)*60
        # Conditional trajectory: observed prior fixture buckets age naturally.
        eligible=[(int(n),float(last)) for minute,n,last in denial_buckets
                  if int(minute)>=boundary-240 and float(last)>end-300]
        count=sum(n for n,last in eligible)
        age=max(0,end-max(last for n,last in eligible)) if eligible else None
        # Expected requests per five minutes at the estimated steady rate.
        # Rounded only for the existing bounded descriptive-index function.
        normal=int(math.floor(5*rate+.5))
        points.append({"horizon_seconds":h,"expected_page_requests":round(rate*h/60,3),
                       "conditional_index":observed_index(normal,count,age)})
    return {"source":"recorded_http_traffic_forecast_v1","issued_at":now,
            "history_minutes":len(history),"audit_samples":len(errors),
            "method":"ewma" if use_ewma else "persistence",
            "ewma_mae":round(mae,4),"persistence_mae":round(base_mae,4),
            "expected_requests_per_minute":round(rate,3),"trajectory":points,
            "score":points[0]["conditional_index"],
            "condition":"no_new_fixture_denials","is_attack_probability":False,
            "automatic_containment":False,"validation_scope":"rolling_internal_page_count_audit"}
