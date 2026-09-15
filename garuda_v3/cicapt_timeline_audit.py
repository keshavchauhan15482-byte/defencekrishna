"""Export candidate provenance events without silently promoting them to truth.

The mirror's binary labels lack a verified completeness/clock alignment contract.
Zeros never establish clean network windows; process first-seen is not compromise.
"""
import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path
from .multisource import sha256


def audit(path):
    counts=Counter();events=[];missing=0;seen=set()
    with open(path,newline='') as f:
        for row in csv.DictReader(f):
            counts[(row['label'],row['subLabel'])]+=1
            if row['label']!='1':continue
            value=next((row.get(k) for k in ('seen time','start time','time') if row.get(k)),None)
            try: t=float(value)
            except (ValueError,TypeError):missing+=1;continue
            if not math.isfinite(t):missing+=1;continue
            key=(row['id'],t,row['subLabel'])
            if key in seen:continue
            seen.add(key)
            events.append(dict(epoch=t,source_id=row['id'],entity_type=row['type'],
                publisher_stage=row['subLabel'],network_stage_validated=False))
    return dict(source_filename=Path(path).name,source_sha256=sha256(path),
        label_counts=[dict(label=k[0],stage=k[1],rows=n) for k,n in sorted(counts.items())],
        labelled_rows_without_numeric_timestamp=missing,events=sorted(events,key=lambda e:e['epoch']),
        status='candidate_provenance_events_only',risk_labels_applied=False,stage_labels_applied=False,
        limitations=['Mirror labels not verified against Caldera Attack_info.csv',
            'Process/Artifact labels are not packet labels',
            'Zero labels do not prove complete negative coverage',
            'First seen timestamps do not establish compromise time',
            'Discovery is not automatically pre-compromise Reconnaissance'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input');p.add_argument('--output',required=True)
    a=p.parse_args();Path(a.output).write_text(json.dumps(audit(a.input),indent=2))
