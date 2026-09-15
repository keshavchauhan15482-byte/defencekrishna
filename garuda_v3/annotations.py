"""Audited timeline sidecars. Unknown time/stage labels stay unknown.
Epoch seconds are UTC; intervals are half open. Only fully covered windows are labelled.
A stage value 0 is an explicit reviewed absence, not the absence of an annotation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from .data import convert, save_dataset
from .pcap import convert_pcap

STAGES = ['reconnaissance','initial_access','lateral_movement','command_and_control','exfiltration']
MITRE = ['TA0043','TA0001','TA0008','TA0011','TA0010']

def finite_time(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not np.isfinite(value):
        raise ValueError('Times must be finite UTC epoch seconds')
    return float(value)

def annotate(data, document):
    if document.get('source_sha256') != data['metadata']['source_sha256']:
        raise ValueError('Annotation source hash does not match capture')
    if not isinstance(document.get('campaign_id'),str) or not document['campaign_id'].strip():
        raise ValueError('Reviewed campaign_id required')
    records=document.get('intervals',[])
    if not records: raise ValueError('Explicit reviewed intervals required')
    records=sorted(records,key=lambda r:finite_time(r['start']))
    end=-float('inf')
    for r in records:
        start=finite_time(r['start']);stop=finite_time(r['end'])
        if start>=stop or start<end: raise ValueError('Overlapping or invalid annotation intervals')
        if r.get('label') not in (0,1) or not isinstance(r.get('evidence'),str) or not r['evidence'].strip():
            raise ValueError('Binary reviewed label and evidence reference required')
        stages=r.get('stages',{})
        if not isinstance(stages,dict) or any(k not in STAGES or v not in (0,1) for k,v in stages.items()):
            raise ValueError('Invalid supervised stage label')
        if r['label']==0 and any(stages.values()): raise ValueError('Benign interval cannot contain positive attack stage')
        end=stop
    result={**data,'metadata':dict(data['metadata'])}
    y=np.full(len(data['times']),-1,dtype=np.int8)
    stage_y=np.full((len(y),len(STAGES)),-1,dtype=np.int8)
    step=data['metadata']['window_seconds']
    for i,t in enumerate(data['times']):
        for r in records:
            if r['start']<=t and t+step<=r['end']:
                if data['y'][i]>=0 and data['y'][i]!=r['label']:
                    raise ValueError('Timeline conflicts with existing flow label')
                y[i]=r['label']
                for j,name in enumerate(STAGES):stage_y[i,j]=r.get('stages',{}).get(name,-1)
                break
    incidents=document.get('incidents',[]);seen=set()
    for incident in incidents:
        identity=incident.get('incident_id')
        if not isinstance(identity,str) or not identity.strip() or identity in seen: raise ValueError('Unique incident_id required')
        seen.add(identity)
        time=finite_time(incident['compromise_time'])
        if not isinstance(incident.get('evidence'),str) or not incident['evidence'].strip(): raise ValueError('Verified compromise evidence reference required')
        if not any(r['start']<=time<r['end'] and r['label']==1 for r in records):
            raise ValueError('Compromise time must fall in reviewed malicious coverage')
    result['y']=y;result['stage_y']=stage_y
    result['metadata'].update(campaign_id=document['campaign_id'],stages=STAGES,mitre_tactics=MITRE,
        annotation_sha256=hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest(),
        annotation_intervals=records,incidents=incidents,annotation_status='user supplied evidence; independently verify references')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture');p.add_argument('--kind',choices=['csv','pcap'],required=True)
    p.add_argument('--annotations',required=True);p.add_argument('--output',required=True)
    p.add_argument('--mode',choices=['host','service'],default='host')
    args=p.parse_args()
    output=Path(args.output)
    if output.exists():p.error('Output already exists; choose a new path')
    data=(convert_pcap if args.kind=='pcap' else convert)(args.capture,mode=args.mode)
    data=annotate(data,json.loads(Path(args.annotations).read_text()))
    save_dataset(data,output)
    print(json.dumps({'windows':len(data['y']),'labelled_windows':int((data['y']>=0).sum()),
        'known_stage_entries':int((data['stage_y']>=0).sum()),'mode':args.mode,'packet_features':data['metadata']['packet_features']}))

if __name__=='__main__':main()
