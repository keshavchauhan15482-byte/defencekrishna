"""Audit exact native five-stage CSV sources across UWF 2024 datasets.

Uses publisher class directories only; no proxy mapping. The audit discovers the single
CSV shard in each required class folder, downloads it, records hash/schema/row count and
checks whether the five classes have sufficient records for a supervised network-record
head before any training split is frozen.
"""
from __future__ import annotations
import argparse,csv,hashlib,html.parser,json,urllib.parse,urllib.request
from pathlib import Path

SOURCES={
 'reconnaissance':('UWF-ZeekDataFall24-2','Reconnaissance'),
 'initial_access':('UWF-ZeekDataFall24-2','Initial_Access'),
 'lateral_movement':('UWF-ZeekDataFall24-2','Lateral_Movement'),
 'command_and_control':('UWF-ZeekDataFall24-2','Command_and_Control'),
 'exfiltration':('UWF-ZeekData24','Exfiltration'),
}
BASE='https://datasets.uwf.edu/data'
class P(html.parser.HTMLParser):
 def __init__(self): super().__init__(); self.links=[]
 def handle_starttag(self,t,a):
  if t.lower()=='a':
   h=dict(a).get('href')
   if h: self.links.append(h)
def get(url):
 req=urllib.request.Request(url,headers={'User-Agent':'Garuda-V124-native-stage/1.0'})
 with urllib.request.urlopen(req,timeout=180) as r:return r.read()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--cache-dir',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();args.cache_dir.mkdir(parents=True,exist_ok=True)
 out={}; schemas={}
 for stage,(ds,folder) in SOURCES.items():
  d=f"{BASE}/{ds}/csv/{folder}/"; parser=P();parser.feed(get(d).decode('utf-8','replace'))
  links=[x for x in parser.links if x.lower().endswith('.csv')]
  if len(links)!=1: raise RuntimeError(f'{stage}: expected one CSV, got {links}')
  url=urllib.parse.urljoin(d,links[0]); raw=get(url); path=args.cache_dir/f'{stage}.csv';path.write_bytes(raw)
  h=hashlib.sha256(raw).hexdigest(); text=raw.decode('utf-8-sig','replace').splitlines(); reader=csv.DictReader(text); rows=list(reader); fields=reader.fieldnames or []
  schemas[stage]=fields
  sample={k:(rows[0].get(k,'')[:200] if rows else '') for k in fields}
  out[stage]={'dataset':ds,'folder':folder,'url':url,'bytes':len(raw),'sha256':h,'rows':len(rows),'columns':fields,'sample_first_row':sample}
 common=set.intersection(*(set(v) for v in schemas.values())) if schemas else set()
 numeric_candidates=sorted(c for c in common if c.lower() in {'duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','src_port_zeek','dest_port_zeek','id.orig_p','id.resp_p'})
 counts={k:v['rows'] for k,v in out.items()}; enough=all(n>=5 for n in counts.values())
 report={'schema_version':'v124-2024-source-audit.1','status':'NATIVE_FIVE_STAGE_TRAINABLE_SOURCE_FOUND' if enough else 'NATIVE_FIVE_STAGE_SOURCE_TOO_SPARSE','proxy_mapping_used':False,'sources':out,'row_counts':counts,'common_columns':sorted(common),'numeric_feature_candidates':numeric_candidates,'minimum_rows_per_class_for_training':5,'all_classes_minimum_met':enough}
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'counts':counts,'common_columns':report['common_columns'],'numeric':numeric_candidates},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
