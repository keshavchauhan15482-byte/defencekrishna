"""V111 postmortem only: characterize the failed frozen run without model inference.

This is not a second scoring attempt. It verifies the frozen V108 runtime preflight and
runs the unchanged strict packet reader only to identify where capture compatibility
failed. No graph model forward pass, persistence metric, support score, threshold, or
adapter change is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import FEATURES, SCHEMA

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
SUPPORT_SHA256 = "7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1"
CAPTURE_SHA256 = "cf478922f789926dab81f212a1a64d604b849068908c5c8885f42cdc32206ae3"
CAPTURE_BYTES = 206480954


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def global_header(path: Path):
    raw=path.read_bytes()[:24]
    out={'first24_hex':raw.hex(),'classic':False,'linktype':None,'snaplen':None}
    if len(raw)<24: return out
    table={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
    if raw[:4] in table:
        endian=table[raw[:4]]
        major,minor,_,_,snaplen,linktype=struct.unpack(endian+'HHIIII',raw[4:])
        out.update({'classic':True,'major':major,'minor':minor,'linktype':linktype,'snaplen':snaplen})
    elif raw[:4]==b'\x0a\x0d\x0d\x0a':
        out['pcapng']=True
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap',required=True,type=Path)
    p.add_argument('--model',required=True,type=Path)
    p.add_argument('--support-gate',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    if args.output.exists(): p.error('postmortem output already exists')

    preflight={}
    preflight['capture_bytes_match']=args.pcap.stat().st_size==CAPTURE_BYTES
    preflight['capture_sha256_match']=sha256(args.pcap)==CAPTURE_SHA256
    preflight['model_sha256_match']=sha256(args.model)==MODEL_SHA256
    preflight['support_gate_sha256_match']=sha256(args.support_gate)==SUPPORT_SHA256
    model,meta=GraphWorldModel.load(args.model)
    preflight['model_contract']={
        'architecture':model.config['architecture'],'decoder':model.config['decoder'],
        'schema':model.schema,'feature_count':int(model.f),'history':int(meta.get('history',-1)),
        'horizon':int(meta.get('horizon',-1)),'mode':meta.get('mode'),
        'window_seconds':int(meta.get('window_seconds',-1)),'max_nodes':int(meta.get('max_nodes',-1)),
        'packet_features_trained':bool(meta.get('packet_features_trained')),
        'ps_complete_features_trained':bool(meta.get('ps_complete_features_trained')),
        'feature_order_match':list(meta.get('features',[]))==list(FEATURES),
    }
    expected={
        'architecture':'gnn_lstm','decoder':'residual','schema':SCHEMA,'feature_count':34,
        'history':8,'horizon':4,'mode':'service','window_seconds':10,'max_nodes':32,
        'packet_features_trained':True,'ps_complete_features_trained':True,'feature_order_match':True,
    }
    preflight['frozen_runtime_preflight_passed']=(all(v is True for k,v in preflight.items() if k.endswith('_match')) and preflight['model_contract']==expected)

    decoded=0; first=None; last=None; parser_error=None
    try:
        for pkt in packets(args.pcap,max_packets=2_000_000):
            decoded+=1
            if first is None: first=float(pkt['t'])
            last=float(pkt['t'])
    except Exception as exc:
        parser_error={'type':type(exc).__name__,'message':str(exc)}

    report={
        'schema_version':'v111-postmortem.1',
        'status':'POSTMORTEM_ONLY_NO_SCORING',
        'claim_boundary':'No model forward pass, persistence metric, support score, threshold fitting, adapter change, or result-improving rerun is performed.',
        'global_header':global_header(args.pcap),
        'frozen_runtime_preflight':preflight,
        'strict_parser':{
            'decoded_ipv4_before_failure':decoded,'first_timestamp':first,'last_timestamp':last,
            'error':parser_error,'completed_without_error':parser_error is None,
        },
        'model_inference_performed':False,
        'state_metric_computed':False,
        'support_metric_computed':False,
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps(report,indent=2,allow_nan=False))

if __name__=='__main__': main()
