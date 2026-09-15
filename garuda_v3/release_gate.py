"""Evidence gates, not a rating or certification. Missing evidence fails closed."""
import argparse
import json
from pathlib import Path
from .inference import ForecastService

def report(folder=None):
    folder=Path(folder) if folder else Path(__file__).parent/'artifacts/residual_run'
    service=ForecastService(folder);metrics=service.metrics;meta=service.meta
    g=metrics['models']['gnn_lstm'];clean=g['clean_history_test']
    incident=g.get('incident_evaluation',{});stages=g.get('supervised_stages',[])
    ci=g.get('state_evidence',{}).get('paired_block_bootstrap_95pct',[None,None])
    stage_support=len(stages)==5 and all(s.get('validation_supported') and s['test'].get('positives',0)>=30
        and s['test'].get('samples',0)-s['test'].get('positives',0)>=30 and s['test'].get('recall',0)>0 for s in stages)
    gates={
        'trained_graph_temporal_model':bool(meta.get('trained')),
        'future_targets_and_baseline_report':True,
        'primary_gnn_f1_exceeds_lr':g['test']['f1']>metrics['models']['logistic_regression']['test']['f1'],
        'gnn_state_error_beats_persistence':g['state_mse']<metrics['state_persistence_mse'],
        'paired_state_error_interval_below_zero':ci[1] is not None and ci[1]<0,
        'adequate_clean_history_positive_cases':clean.get('positives',0)>=30,
        'verified_clean_history_incident_warning':incident.get('clean_history_eligible_incidents',0)>=30 and (incident.get('clean_history_event_recall') or 0)>0,
        'validated_mitre_stage_supervision':stage_support,
        'host_and_packet_trained_checkpoint':meta.get('mode')=='host' and bool(meta.get('packet_features_trained')),
        'independent_campaign_evaluation':False,
        'independent_security_and_load_review':False,
    }
    return {'market_ready':all(gates.values()),'gates':gates,
        'purpose':'prevent unsupported readiness claims; minimum counts are internal engineering checks, not official SIH criteria or certification',
        'scope':metrics.get('evaluation_scope','internal temporal holdout'),'independent_review_status':'not supplied'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--artifacts')
    print(json.dumps(report(parser.parse_args().artifacts),indent=2))
