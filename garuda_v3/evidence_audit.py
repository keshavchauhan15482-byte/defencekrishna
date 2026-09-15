"""Count actual annotation support. Never infer compromise or tactics from attack names."""
import argparse,json
from pathlib import Path
import numpy as np
from .data import load_dataset
from .annotations import STAGES

def audit(paths):
 rows=[]
 for path in paths:
  d=load_dataset(path);m=d['metadata'];stage=d.get('stage_y',np.full((len(d['y']),len(STAGES)),-1))
  rows.append(dict(file=str(path),capture_sha256=m['source_sha256'],campaign=m.get('campaign_id'),family=m.get('attack_family'),label_status=m.get('annotation_status','unknown'),timezone_assumption=m.get('timezone_assumption'),windows=len(d['y']),binary_labels={str(v):int((d['y']==v).sum()) for v in [-1,0,1]},verified_incident_records=len(m.get('incidents',[])),stages={name:dict(positive=int((stage[:,j]==1).sum()),negative=int((stage[:,j]==0).sum()),unknown=int((stage[:,j]<0).sum())) for j,name in enumerate(STAGES)}))
 return dict(captures=rows,review_required=['Confirm timestamp timezone from capture/system logs','Supply evidence references for successful compromise times; attack-start times are not compromise times','Review positive and explicit-negative tactic intervals separately; missing entries remain unknown'],supervised_stage_training_ready=all(any(r['stages'][s]['positive'] for r in rows) and any(r['stages'][s]['negative'] for r in rows) for s in STAGES),warning_evidence_ready=any(r['verified_incident_records'] for r in rows),limitation='Presence of supplied references is not independent verification.')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--graphs',nargs='+',required=True);p.add_argument('--output',required=True);a=p.parse_args();Path(a.output).write_text(json.dumps(audit(a.graphs),indent=2))
if __name__=='__main__':main()
