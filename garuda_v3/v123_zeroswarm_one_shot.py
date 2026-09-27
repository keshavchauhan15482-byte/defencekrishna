"""V123 frozen all-PCAP ZeroSWARM external forecasting evaluation.

All four publisher PCAP identities are frozen before packet decode. The runner uses the
frozen V116 model, V118 validation-only calibration and V122 semantic runtime support.
The V120 envelope is reported only as a behavior-shift diagnostic and is not a hard
compatibility veto. No labels or external statistics are used for fitting or selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES
from .v101_packet_graph_recovery import HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, build_sequences, infer_state, persistence_prediction
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import RELATIVE_SCHEMA, RAW_SCHEMA, apply_transform, inverse_pooled
from .v120_robust_support_envelope import decisions as behavior_decisions
from .v122_semantic_support_contract import semantic_decisions

MODEL_SHA256="1c326e66f487f5947f526c68469025ffb3410b6f0e63bfc3ee0e9f72ba81031c"
TRANSFORM_SHA256="6d5dee6ce930ed041e9921e5f5d1e8281838eb3799c96f338ed3a9d8a7e37643"
CALIBRATION_SHA256="c130d235cfcc59803cc27b29cfe67b6e8245b1b8296f98dd3acfe922d023b701"
SEMANTIC_SUPPORT_SHA256="2b248bdb0c9504598d8feecb5a09bdcb322db605872839c684f235c938fec564"
BEHAVIOR_GATE_SHA256="3218ff33b0ada393b1a6aa16c9d5948a848a2d6648a9f900c07bd9c91c8028c4"
MIN_SEQUENCES=32
MIN_SEMANTIC_SUPPORT=0.95
MAX_PACKETS=2_000_000

class V123ContractError(RuntimeError): pass

def file_hash(path: Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pcap-dir',required=True,type=Path)
    ap.add_argument('--model',required=True,type=Path)
    ap.add_argument('--relative-transform',required=True,type=Path)
    ap.add_argument('--calibration',required=True,type=Path)
    ap.add_argument('--semantic-support-contract',required=True,type=Path)
    ap.add_argument('--behavior-gate',required=True,type=Path)
    ap.add_argument('--prereg',required=True,type=Path)
    ap.add_argument('--acquisition',required=True,type=Path)
    ap.add_argument('--execution-lock',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    args=ap.parse_args()
    if args.output.exists(): raise V123ContractError('V123 result already exists and is immutable')

    p=json.loads(args.prereg.read_text()); a=json.loads(args.acquisition.read_text()); lock=json.loads(args.execution_lock.read_text())
    if p.get('status')!='HASH_FROZEN_ONE_SHOT_ARMED' or p.get('evaluation_permitted') is not True: raise V123ContractError('Preregistration not armed')
    if a.get('status')!='HASH_FROZEN_NO_PACKET_DECODE' or a.get('file_count')!=4: raise V123ContractError('Acquisition manifest invalid')
    if a.get('packet_records_decoded') is not False or a.get('model_inference_performed') is not False or a.get('labels_accessed') is not False: raise V123ContractError('Acquisition boundary violated')
    if lock.get('status')!='IRREVERSIBLE_PRE_DECODE_LOCK': raise V123ContractError('Execution lock missing')
    if lock.get('packet_records_decoded_before_lock') is not False or lock.get('model_inference_performed_before_lock') is not False: raise V123ContractError('Lock boundary violated')

    expected_paths={
        'model_sha256':(args.model,MODEL_SHA256),
        'relative_transform_sha256':(args.relative_transform,TRANSFORM_SHA256),
        'innovation_calibration_sha256':(args.calibration,CALIBRATION_SHA256),
        'semantic_support_contract_sha256':(args.semantic_support_contract,SEMANTIC_SUPPORT_SHA256),
        'robust_behavior_gate_sha256':(args.behavior_gate,BEHAVIOR_GATE_SHA256),
    }
    reg=p['registered_candidate']
    for key,(path,expected) in expected_paths.items():
        if file_hash(path)!=expected or reg.get(key)!=expected or lock.get(key)!=expected: raise V123ContractError(f'Frozen runtime mismatch: {key}')

    calibration=json.loads(args.calibration.read_text()); alpha=float(calibration.get('alpha',-1))
    if not 0.0<alpha<=1.0 or calibration.get('external_used_for_fit') is not False or calibration.get('consumed_external_used_for_fit') is not False: raise V123ContractError('Calibration provenance invalid')
    transform=json.loads(args.relative_transform.read_text())
    if transform.get('model_schema')!=RELATIVE_SCHEMA or transform.get('raw_schema')!=RAW_SCHEMA or transform.get('future_information_used_for_transform') is not False: raise V123ContractError('Transform contract invalid')
    semantic=json.loads(args.semantic_support_contract.read_text())
    if semantic.get('status')!='FROZEN' or semantic.get('provenance',{}).get('all_consumed_external_holdouts_excluded') is not True: raise V123ContractError('Semantic support provenance invalid')
    behavior=json.loads(args.behavior_gate.read_text())
    if behavior.get('fit_provenance',{}).get('all_consumed_external_holdouts_excluded_from_fit') is not True: raise V123ContractError('Behavior diagnostic provenance invalid')

    model,meta=GraphWorldModel.load(args.model)
    if model.schema!=RELATIVE_SCHEMA or model.f!=len(FEATURES) or meta.get('raw_input_schema')!=RAW_SCHEMA: raise V123ContractError('Model schema mismatch')
    if not bool(meta.get('packet_features_trained')) or not bool(meta.get('ps_complete_features_trained')): raise V123ContractError('Model not PS-complete packet-trained')
    if list(meta.get('features',[]))!=list(FEATURES): raise V123ContractError('Feature ordering mismatch')

    frozen={x['name']:x for x in a['files']}
    expected_names=[x['name'] for x in p['external_holdout']['expected_files']]
    if set(frozen)!=set(expected_names) or len(expected_names)!=4: raise V123ContractError('Frozen file set mismatch')

    all_model=[]; all_cal=[]; all_persist=[]; all_target=[]; all_sem=[]; all_beh=[]; per_capture=[]
    total_decoded=0; packet_num=0.0; packet_den=0; all_cutoffs=[]
    for name in expected_names:
        meta_f=frozen[name]; path=args.pcap_dir/name
        if not path.exists() or path.stat().st_size!=int(meta_f['bytes']) or file_hash(path)!=meta_f['sha256']: raise V123ContractError(f'PCAP identity mismatch: {name}')
        times,raw_x,adj,mask,decoded,audit=tolerant_packet_service_graphs(path,MAX_PACKETS)
        total_decoded+=int(decoded)
        packet_idx=FEATURES.index('packet_features_present'); vals=raw_x[:,:,packet_idx][mask>0]
        packet_num+=float(vals.sum()); packet_den+=int(len(vals))
        try:
            sx_raw,sa,sm,target_raw,cutoffs=build_sequences(times,raw_x,adj,mask)
        except Exception as exc:
            raise V123ContractError(f'No valid contiguous sequence for required capture {name}: {exc}') from exc
        if len(sx_raw)<1: raise V123ContractError(f'Required capture has zero sequences: {name}')
        sx_rel,_,centers=apply_transform(sx_raw,target_raw,sm,transform)
        model_rel=infer_state(model,sx_rel,sa,sm); persist_rel=persistence_prediction(sx_rel,sm)
        model_raw=inverse_pooled(model_rel,centers,transform); persist_raw=inverse_pooled(persist_rel,centers,transform)
        calibrated=persist_raw+alpha*(model_raw-persist_raw)
        sem=semantic_decisions(sx_raw,sx_rel,sm)['supported']
        beh_scores,_,_,beh_supported=behavior_decisions(behavior,sx_rel,sm)
        all_model.append(model_raw); all_cal.append(calibrated); all_persist.append(persist_raw); all_target.append(target_raw); all_sem.append(sem); all_beh.append(beh_supported); all_cutoffs.append(cutoffs.astype(np.int64))
        per_capture.append({'name':name,'bytes':int(meta_f['bytes']),'sha256':meta_f['sha256'],'decoded_ipv4_packets':int(decoded),'observed_windows':int(len(times)),'contiguous_sequences':int(len(sx_raw)),'semantic_supported_fraction':float(sem.mean()),'behavior_envelope_supported_fraction':float(beh_supported.mean()),'behavior_median_exceedance_fraction':float(np.median(beh_scores)),'parser_audit':audit})

    model_raw=np.concatenate(all_model,axis=0); calibrated=np.concatenate(all_cal,axis=0); persist=np.concatenate(all_persist,axis=0); target=np.concatenate(all_target,axis=0)
    sem=np.concatenate(all_sem); beh=np.concatenate(all_beh); cutoffs=np.concatenate(all_cutoffs)
    base_mse=float(np.mean((model_raw-target)**2,dtype=np.float64)); cal_mse=float(np.mean((calibrated-target)**2,dtype=np.float64)); pers_mse=float(np.mean((persist-target)**2,dtype=np.float64))
    improvement=float((pers_mse-cal_mse)/pers_mse) if pers_mse else 0.0; base_improvement=float((pers_mse-base_mse)/pers_mse) if pers_mse else 0.0
    n=int(len(sem)); sem_frac=float(sem.mean()) if n else 0.0; beh_frac=float(beh.mean()) if n else 0.0
    enough=n>=MIN_SEQUENCES; support_ok=sem_frac>=MIN_SEMANTIC_SUPPORT; all_have=all(x['contiguous_sequences']>=1 for x in per_capture); beats=cal_mse<pers_mse; positive=improvement>0; finite=bool(np.isfinite([base_mse,cal_mse,pers_mse,improvement,base_improvement]).all())
    passed=bool(enough and support_ok and all_have and beats and positive and finite)
    result={
      'schema_version':'v123.1','status':'PASS' if passed else 'FAIL',
      'gate':{'minimum_total_sequences_across_all_pcaps':MIN_SEQUENCES,'minimum_semantic_support_fraction':MIN_SEMANTIC_SUPPORT,'total_sequences_gate_passed':enough,'semantic_support_gate_passed':support_ok,'all_four_pcaps_have_valid_sequence':all_have,'persistence_gate_passed':beats,'positive_improvement_gate_passed':positive,'finite_metrics_gate_passed':finite,'all_gates_passed':passed},
      'dataset':{'name':p['external_holdout']['dataset'],'publisher':p['external_holdout']['publisher'],'zenodo_record':'15082260','doi':p['external_holdout']['doi'],'file_count':4,'labels_accessed':False,'captures':per_capture},
      'frozen_runtime':{'base_model_sha256':MODEL_SHA256,'relative_transform_sha256':TRANSFORM_SHA256,'innovation_calibration_sha256':CALIBRATION_SHA256,'semantic_support_contract_sha256':SEMANTIC_SUPPORT_SHA256,'robust_behavior_gate_sha256':BEHAVIOR_GATE_SHA256,'alpha':alpha,'raw_schema':RAW_SCHEMA,'model_schema':RELATIVE_SCHEMA,'feature_count':len(FEATURES),'history_windows':HISTORY,'forecast_windows':HORIZON,'window_seconds':WINDOW_SECONDS,'max_nodes':MAX_NODES},
      'capture_processing':{'decoded_ipv4_packets_total':total_decoded,'aggregate_contiguous_sequences':n,'packet_features_present_mean_on_observed_nodes':float(packet_num/packet_den) if packet_den else 0.0,'cutoff_timestamps_sha256':hashlib.sha256(cutoffs.tobytes()).hexdigest()},
      'state_forecasting':{'metric':'raw reconstructed pooled-state MSE','base_v116_model_mse_diagnostic':base_mse,'calibrated_v118_mse':cal_mse,'persistence_mse':pers_mse,'base_v116_improvement_vs_persistence_diagnostic':base_improvement,'calibrated_improvement_vs_persistence':improvement,'calibrated_beats_persistence':beats},
      'runtime_support':{'method':'V122 semantic runtime compatibility','supported_sequences':int(sem.sum()),'total_sequences':n,'supported_fraction':sem_frac,'minimum_fraction':MIN_SEMANTIC_SUPPORT},
      'behavior_shift_diagnostic':{'method':behavior.get('method'),'hard_veto':False,'envelope_supported_sequences':int(beh.sum()),'total_sequences':n,'envelope_supported_fraction':beh_frac,'interpretation':'distribution-shift diagnostic only; not attack/OOD detection and not input-contract compatibility'},
      'one_shot_integrity':{'runs_allowed_for_claim':1,'model_inference_performed_once':True,'retrained_on_external':False,'transform_fit_on_external':False,'calibration_fit_on_external':False,'support_fit_on_external':False,'labels_accessed':False,'all_four_pcaps_processed':True,'rerun_for_claim_improvement':False},
      'claim_boundary':'Fresh publisher-independent external state-transition forecasting only. No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made.'
    }
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n'); print(json.dumps(result,indent=2,allow_nan=False)); return 0

if __name__=='__main__': raise SystemExit(main())
