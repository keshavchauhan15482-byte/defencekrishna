"""Prepare the predeclared held-out infiltration victim capture, preserving uncertain labels."""
from pathlib import Path
from datetime import datetime,timezone
import json,numpy as np
from .ids2018_prepare import clean
from .pcap import convert_pcap
from .pcap_reader import packets
from .data import save_dataset

def main():
 import argparse
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',default='datasets/ids2018/diverse_v8');parser.add_argument('--max-nodes',type=int,choices=[64,128,256,512],default=64);args=parser.parse_args()
 root=Path(args.root);protocol=json.loads((root/'protocol.json').read_text())
 if (root/'labelled_graph.npz').exists():raise ValueError('Prepared capture already exists; do not overwrite')
 path,audit=clean(root/'Wednesday-28-02-2018.pcap',root)
 d=convert_pcap(path,window_seconds=60,max_nodes=args.max_nodes,max_packets=2000000)
 keep=~np.isin(d['times'],audit['excluded_windows'])
 for k in ('x','adj','mask','y','times'):d[k]=d[k][keep]
 d['metadata']['node_names']=[v for v,k in zip(d['metadata']['node_names'],keep) if k]
 ranges=[tuple(datetime.fromisoformat('2018-02-28T'+v).replace(tzinfo=timezone.utc).timestamp()+4*3600 for v in interval) for interval in protocol['schedule']]
 peers=set()
 for p in packets(path,max_packets=2000000):
  if protocol['attacker'] in (p['src'],p['dst']):peers.add(int(p['t']//60)*60)
 y=[]
 for t in d['times']:
  full=any(a+60<=t and t+60<=b-60 for a,b in ranges);overlap=any(t<b+60 and t+60>a-60 for a,b in ranges)
  y.append(1 if full and t in peers else -1 if overlap or t in peers else 0)
 d['y']=np.asarray(y,dtype=np.int8)
 d['metadata'].update(campaign_id='Wednesday-28-02-2018',attack_family='infiltration',annotation_status='schedule-assisted weak labels; partial victim capture',timezone_assumption=protocol['timezone_assumption'],incidents=[],windows=len(y),preprocessing_audit=audit)
 save_dataset(d,root/'labelled_graph.npz');print('Prepared held-out graph; no label counts inspected for model choices')
if __name__=='__main__':main()
