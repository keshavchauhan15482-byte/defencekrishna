"""Incident-level accounting: count misses and coverage, not just successful alerts.
Risks remain malicious-flow forecasts; lead time is measured against externally
verified compromise timestamps, not inferred from labels or risk thresholds.
"""
import numpy as np

def evaluate(datasets, indices, probabilities, history, horizon, threshold):
    p=np.asarray(probabilities)
    if p.shape!=(len(indices),horizon) or not np.isfinite(p).all() or np.any((p<0)|(p>1)):
        raise ValueError('Invalid event prediction array')
    rows=[];eligible=0;detected=0;clean_eligible=0;clean_detected=0
    evaluated_sources={s for s,_ in indices}
    for source,d in enumerate(datasets):
        if source not in evaluated_sources:continue
        step=d['metadata']['window_seconds']
        for incident in d['metadata'].get('incidents',[]):
            target=incident['compromise_time']; candidates=[];clean_candidates=[]
            for j,(s,start) in enumerate(indices):
                if s!=source:continue
                cutoff=int(d['times'][start+history-1])+step
                if not cutoff<target<=cutoff+horizon*step:continue
                # Only risks up to the window containing verified compromise count.
                k=int(np.ceil((target-cutoff)/step))
                alert=bool((p[j,:k]>=threshold).any())
                candidates.append((cutoff,alert))
                if np.all(d['y'][start:start+history]==0):clean_candidates.append((cutoff,alert))
            alerts=[c for c,a in candidates if a];clean_alerts=[c for c,a in clean_candidates if a]
            eligible+=bool(candidates);detected+=bool(alerts)
            clean_eligible+=bool(clean_candidates);clean_detected+=bool(clean_alerts)
            rows.append(dict(source_sha256=d['metadata']['source_sha256'],incident_id=incident['incident_id'],
                evidence=incident['evidence'],eligible=bool(candidates),alerted=bool(alerts),
                clean_history_eligible=bool(clean_candidates),clean_history_alerted=bool(clean_alerts),
                lead_seconds=target-min(alerts) if alerts else None,
                clean_history_lead_seconds=target-min(clean_alerts) if clean_alerts else None))
    # False alert burden only on fully known benign future flow windows.
    negatives=[]
    for j,(s,start) in enumerate(indices):
        labels=datasets[s]['y'][start+history:start+history+horizon]
        if len(labels)==horizon and np.all(labels==0):negatives.append(bool((p[j]>=threshold).any()))
    return dict(status='evaluated' if rows else 'no_verified_incident_annotations',incidents=rows,
        incident_scope='All annotated incidents in evaluated captures; no candidate window means uncovered, never a successful warning',
        total_incidents=len(rows),eligible_incidents=eligible,uncovered_incidents=len(rows)-eligible,
        detected_incidents=detected,missed_eligible_incidents=eligible-detected,
        event_recall=detected/eligible if eligible else None,
        clean_history_eligible_incidents=clean_eligible,clean_history_detected_incidents=clean_detected,
        clean_history_event_recall=clean_detected/clean_eligible if clean_eligible else None,
        fully_benign_future_examples=len(negatives),false_alert_examples=sum(negatives),
        benign_future_alert_fraction=sum(negatives)/len(negatives) if negatives else None,
        limitation='External timestamps are supplied annotations, not independently authenticated. Overlapping examples are correlated; flow risk is not a calibrated compromise probability.')
