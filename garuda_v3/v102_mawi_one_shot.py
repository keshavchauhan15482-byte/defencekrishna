"""V102 preregistered MAWI one-shot state-transition evaluation.

Uses the frozen V101 packet-compatible GraphSAGE+LSTM checkpoint and the
acquisition-frozen MAWI hashes. MAWI's 96-byte snaplen is handled without
fabricating payload bytes: required IPv4/TCP/UDP headers must be captured and
payload length is derived from the IPv4 total-length field. This policy is
frozen before packet-record decoding.
"""
from __future__ import annotations

import argparse, hashlib, json, socket, struct
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterator, List
import numpy as np

from .data import FEATURES, SCHEMA, graph_snapshot
from .model import GraphWorldModel
from .ps_complete import _connection_flow
from .support_gate import score as support_score
from .v101_packet_graph_recovery import build_sequences, infer_state, persistence_prediction

HISTORY=8
HORIZON=4
WINDOW_SECONDS=10
MAX_NODES=32
EXPECTED_CAPTURE='200601011400.dump'
EXPECTED_SNAPLEN=96
EXPECTED_MODEL_SHA256='30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79'
EXPECTED_SUPPORT_SHA256='2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3'
EXPECTED_ADAPTER_SHA256='870e7894378e687c542f286eabccf367c10d4d41dbebe7551b4ce95df2c65ac8'
_CLASSIC={
 b'\xd4\xc3\xb2\xa1':('<',1e6), b'\xa1\xb2\xc3\xd4':('>',1e6),
 b'\x4d\x3c\xb2\xa1':('<',1e9), b'\xa1\xb2\x3c\x4d':('>',1e9),
}

class V102ContractError(RuntimeError): pass

def file_hash(path: Path) -> str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
 return h.hexdigest()

def decode_truncated_ipv4(data:bytes, *, original:int, timestamp:float, linktype:int):
 off=0
 if linktype==1:
  if len(data)<14: raise V102ContractError('Truncated Ethernet header')
  kind=struct.unpack('!H',data[12:14])[0]; off=14
  for _ in range(2):
   if kind in (0x8100,0x88A8):
    if len(data)<off+4: raise V102ContractError('Truncated VLAN header')
    kind=struct.unpack('!H',data[off+2:off+4])[0]; off+=4
  if kind!=0x0800: return None
 elif linktype!=101: raise V102ContractError(f'Unsupported linktype {linktype}')
 ip=data[off:]
 if len(ip)<20 or ip[0]>>4!=4: return None
 ihl=(ip[0]&15)*4
 if ihl<20 or len(ip)<ihl: raise V102ContractError('Truncated IPv4 header')
 total=struct.unpack('!H',ip[2:4])[0]
 if total<ihl: raise V102ContractError('Invalid IPv4 total length')
 frag=struct.unpack('!H',ip[6:8])[0]; proto=ip[9]
 item=dict(t=float(timestamp),src=socket.inet_ntoa(ip[12:16]),dst=socket.inet_ntoa(ip[16:20]),
  bytes=int(original),ttl=int(ip[8]),frag=bool(frag&0x3FFF),protocol='other',sport=0,dport=0,
  flags=0,win=0,seq=None,payload_len=max(0,total-ihl))
 if frag&0x1FFF: return item
 tr=ip[ihl:]; tr_total=max(0,total-ihl)
 if proto==6:
  if len(tr)<20: raise V102ContractError('Snaplen omitted required TCP header bytes')
  thl=(tr[12]>>4)*4
  if thl<20 or thl>tr_total or len(tr)<thl: raise V102ContractError('Incomplete/invalid TCP header')
  sport,dport,seq=struct.unpack('!HHI',tr[:8])
  item.update(protocol='tcp',sport=int(sport),dport=int(dport),seq=int(seq),flags=int(tr[13]),
   win=struct.unpack('!H',tr[14:16])[0],payload_len=max(0,tr_total-thl))
 elif proto==17:
  if len(tr)<8: raise V102ContractError('Snaplen omitted required UDP header bytes')
  sport,dport=struct.unpack('!HH',tr[:4])
  item.update(protocol='udp',sport=int(sport),dport=int(dport),payload_len=max(0,tr_total-8))
 return item

def mawi_packets(path:Path)->Iterator[dict]:
 with path.open('rb') as f:
  magic=f.read(4); tail=f.read(20)
  if magic not in _CLASSIC or len(tail)!=20: raise V102ContractError('Expected classic PCAP')
  endian,unit=_CLASSIC[magic]
  major,minor,_,_,snaplen,linktype=struct.unpack(endian+'HHIIII',tail)
  if (major,minor)!=(2,4) or snaplen!=EXPECTED_SNAPLEN or linktype not in (1,101):
   raise V102ContractError(f'Unexpected PCAP contract: v{major}.{minor} snaplen={snaplen} linktype={linktype}')
  while True:
   rec=f.read(16)
   if not rec: break
   if len(rec)!=16: raise V102ContractError('Truncated packet record')
   sec,sub,captured,original=struct.unpack(endian+'IIII',rec)
   if captured>snaplen or captured>original: raise V102ContractError('Invalid capture length')
   data=f.read(captured)
   if len(data)!=captured: raise V102ContractError('Truncated packet bytes')
   item=decode_truncated_ipv4(data,original=original,timestamp=sec+sub/unit,linktype=linktype)
   if item is not None: yield item

def _flow(rows:List[dict])->dict:
 flow=_connection_flow(rows)
 flow['retransmission_fraction']=float(flow.get('retransmission_count',0.0))/max(float(flow.get('packets',0.0)),1.0)
 return flow

def packet_service_graphs(path:Path):
 times=[]; xs=[]; adjs=[]; masks=[]; current=None; conns:Dict[tuple,List[dict]]=defaultdict(list); decoded=0
 def flush():
  nonlocal conns
  if current is None: return
  flows=[_flow(v) for v in conns.values()]
  x,a,m,_=graph_snapshot(flows,mode='service',max_nodes=MAX_NODES)
  times.append(int(current)); xs.append(x.astype(np.float32)); adjs.append(a.astype(np.float32)); masks.append(m.astype(np.float32)); conns=defaultdict(list)
 for pkt in mawi_packets(path):
  decoded+=1; bucket=int(pkt['t']//WINDOW_SECONDS)*WINDOW_SECONDS
  if current is None: current=bucket
  elif bucket!=current:
   if bucket<current: raise V102ContractError('Non-monotone timestamps')
   flush(); current=bucket
  ep=sorted([(pkt['src'],pkt['sport']),(pkt['dst'],pkt['dport'])]); conns[(ep[0],ep[1],pkt['protocol'])].append(pkt)
 flush()
 if decoded<1000 or len(times)<HISTORY+HORIZON: raise V102ContractError('Insufficient external traffic windows')
 return np.asarray(times,np.int64),np.asarray(xs,np.float32),np.asarray(adjs,np.float32),np.asarray(masks,np.float32),decoded

def evaluate(pcap:Path, model_path:Path, gate_path:Path, prereg_path:Path, acquisition_path:Path)->dict:
 prereg=json.loads(prereg_path.read_text()); acq=json.loads(acquisition_path.read_text())
 if prereg.get('schema_version')!='v102-prereg.1' or acq.get('status')!='HASH_ACQUIRED_MODEL_NOT_RUN': raise V102ContractError('Unfrozen V102 acquisition state')
 if pcap.name!=EXPECTED_CAPTURE or file_hash(pcap)!=acq.get('decompressed_sha256'): raise V102ContractError('MAWI capture/hash mismatch')
 if file_hash(model_path)!=EXPECTED_MODEL_SHA256 or file_hash(gate_path)!=EXPECTED_SUPPORT_SHA256: raise V102ContractError('Frozen V101 runtime hash mismatch')
 reg=prereg['registered_candidate']
 if reg['model_sha256']!=EXPECTED_MODEL_SHA256 or reg['support_gate_sha256']!=EXPECTED_SUPPORT_SHA256 or reg['adapter_contract_sha256']!=EXPECTED_ADAPTER_SHA256: raise V102ContractError('Preregistered candidate changed')
 model,meta=GraphWorldModel.load(model_path)
 contract=dict(architecture=model.config['architecture'],history=int(meta.get('history',-1)),horizon=int(meta.get('horizon',-1)),decoder=model.config['decoder'],mode=meta.get('mode'),window_seconds=int(meta.get('window_seconds',-1)),max_nodes=int(meta.get('max_nodes',-1)))
 expected=dict(architecture='gnn_lstm',history=8,horizon=4,decoder='residual',mode='service',window_seconds=10,max_nodes=32)
 if contract!=expected or not bool(meta.get('packet_features_trained',False)): raise V102ContractError(f'Frozen model contract mismatch: {contract}')
 gate=json.loads(gate_path.read_text())
 times,x,a,m,decoded=packet_service_graphs(pcap); sx,sa,sm,target,cutoffs=build_sequences(times,x,a,m)
 pred=infer_state(model,sx,sa,sm); persist=persistence_prediction(sx,sm)
 mm=float(np.mean((pred-target)**2)); pm=float(np.mean((persist-target)**2)); improvement=float((pm-mm)/pm) if pm else 0.0
 per=[]
 for h in range(HORIZON):
  hm=float(np.mean((pred[:,h]-target[:,h])**2)); hp=float(np.mean((persist[:,h]-target[:,h])**2))
  per.append(dict(seconds_ahead=(h+1)*10,model_mse=hm,persistence_mse=hp,improvement_vs_persistence=float((hp-hm)/hp) if hp else 0.0,beats_persistence=bool(hm<hp)))
 scores=support_score(gate,sx,sm); threshold=float(gate['threshold']); supported=scores<=threshold
 sup=None
 if supported.any():
  smm=float(np.mean((pred[supported]-target[supported])**2)); spm=float(np.mean((persist[supported]-target[supported])**2)); sup=dict(sequences=int(supported.sum()),model_mse=smm,persistence_mse=spm,improvement_vs_persistence=float((spm-smm)/spm) if spm else 0.0,beats_persistence=bool(smm<spm))
 pidx=FEATURES.index('packet_features_present'); vals=x[:,:,pidx][m>0]; passed=bool(mm<pm)
 return dict(schema_version='v102.1',status='PASS' if passed else 'FAIL',gate='frozen V101 state MSE must be lower than persistence MSE on exact preregistered MAWI capture',
  dataset=dict(name=prereg['external_holdout']['dataset'],samplepoint='B',capture_id='200601011400',capture=pcap.name,compressed_sha256=acq['compressed_sha256'],decompressed_sha256=file_hash(pcap),labels_accessed=False),
  frozen_runtime=dict(model_sha256=EXPECTED_MODEL_SHA256,support_gate_sha256=EXPECTED_SUPPORT_SHA256,adapter_contract_sha256=EXPECTED_ADAPTER_SHA256,contract=contract,packet_features_trained=True,risk_head_trained=bool(meta.get('risk_head_trained',False))),
  adapter=dict(schema=SCHEMA,features=list(FEATURES),feature_count=len(FEATURES),mode='service',window_seconds=10,max_nodes=32,snaplen_policy='require complete network/transport headers; derive payload length from IPv4 total-length; never fabricate payload bytes',fit_on_mawi=False,decoded_ipv4_packets=int(decoded),observed_windows=int(len(times)),contiguous_sequences=int(len(sx)),first_window_epoch=int(times[0]),last_window_epoch=int(times[-1]),packet_features_present_mean_on_observed_nodes=float(vals.mean()) if len(vals) else 0.0),
  state_forecasting=dict(model_mse=mm,persistence_mse=pm,improvement_vs_persistence=improvement,beats_persistence=passed,per_horizon=per),
  runtime_support=dict(method=gate.get('method'),threshold=threshold,supported_sequences=int(supported.sum()),total_sequences=int(len(supported)),supported_fraction=float(supported.mean()),median_support_score=float(np.median(scores)),max_support_score=float(scores.max()),supported_only_state_metrics=sup,interpretation='training-support diagnostic only; abstention is not attack/OOD detection'),
  one_shot_integrity=dict(runs_allowed=1,retrained_on_mawi=False,normalization_fit_on_mawi=False,threshold_fit_on_mawi=False,support_fit_on_mawi=False,seed_or_checkpoint_selected_on_mawi=False,attack_labels_accessed=False,rerun_for_claim_improvement=False,cutoff_timestamps=cutoffs.astype(int).tolist()),
  claim_boundary='Fresh external one-shot state-transition forecasting only; no attack recall/FPR, MITRE-stage, or successful-compromise claim.')

def main()->int:
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('--pcap',required=True,type=Path); p.add_argument('--model',required=True,type=Path); p.add_argument('--support-gate',required=True,type=Path); p.add_argument('--prereg',required=True,type=Path); p.add_argument('--acquisition',required=True,type=Path); p.add_argument('--output',required=True,type=Path); args=p.parse_args()
 if args.output.exists(): p.error('V102 one-shot result already exists and is immutable')
 result=evaluate(args.pcap,args.model,args.support_gate,args.prereg,args.acquisition); args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n'); print(json.dumps(result,indent=2,allow_nan=False)); return 0
if __name__=='__main__': raise SystemExit(main())
