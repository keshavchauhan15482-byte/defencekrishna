"""Conservative schedule-assisted labels, NOT verified compromise/stage ground truth."""
from pathlib import Path
from datetime import datetime,timedelta,timezone
from collections import defaultdict
import json,numpy as np
from garuda_v3.data import load_dataset,save_dataset
from garuda_v3.pcap_reader import packets
SCHEDULE={
'Thursday-22-02-2018':('2018-02-22','18.218.115.60','web',[('10:17','11:24'),('13:50','14:29'),('16:15','16:29')]),
'Friday-23-02-2018':('2018-02-23','18.218.115.60','web',[('10:03','11:03'),('13:00','14:10'),('15:05','15:18')]),
'Thursday-01-03-2018':('2018-03-01','13.58.225.34','infiltration',[('09:57','10:55'),('14:00','15:37')]),
'Friday-02-03-2018':('2018-03-02','18.219.211.138','botnet',[('10:11','11:34'),('14:24','15:55')])}
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--data-root',default='datasets/ids2018')
 ROOT=Path(parser.parse_args().data_root)
 manifest={'train':['Thursday-22-02-2018'],'validation':['Friday-23-02-2018'],'test':['Thursday-01-03-2018','Friday-02-03-2018']}
 # Frozen before model training. This small cross-family experiment is exploratory.
 (ROOT/'split.json').write_text(json.dumps(manifest,indent=2))
 for name,(day,attacker,family,intervals) in SCHEDULE.items():
  d=load_dataset(ROOT/'graphs'/(name+'.npz'));peer=defaultdict(int)
  for p in packets(ROOT/'clean'/(name+'.pcap'),max_packets=1000000):
   if attacker in (p['src'],p['dst']):peer[int(p['t']//60)*60]+=1
  ranges=[]
  for start,end in intervals:
   ranges.append(tuple(int((datetime.fromisoformat(day+'T'+v).replace(tzinfo=timezone.utc)+timedelta(hours=4)).timestamp()) for v in (start,end)))
  y=[]
  for t in d['times']:
   full=any(a+60<=t and t+60<=b-60 for a,b in ranges)
   overlap=any(t<b+60 and t+60>a-60 for a,b in ranges)
   y.append(1 if full and peer[int(t)] else -1 if overlap or peer[int(t)] else 0)
  d['y']=np.array(y,dtype=np.int8)
  d['metadata'].update(attack_family=family,annotation_status='schedule-assisted weak labels; not independently verified packet truth',
   label_method='1: published interval interior AND observed attacker endpoint; -1: boundaries, attack interval without matched endpoint, or attacker outside schedule; 0: no matched attacker and outside schedule (benchmark benign assumption)',
   schedule_source='https://www.unb.ca/cic/datasets/ids-2018.html',schedule_utc_ranges=ranges,
   timezone_assumption='Published wall time interpreted UTC-04:00; consistent with web attack packet activity, not a publisher-confirmed timezone declaration',
   annotation_intervals=[],incidents=[],stage_supervised=False)
  save_dataset(d,ROOT/'labelled'/(name+'.npz'))
  print(name,'family',family,'labels',dict(zip(*[a.tolist() for a in np.unique(d['y'],return_counts=True)])),'matched_windows',sum(peer[int(t)]>0 for t in d['times']),flush=True)
