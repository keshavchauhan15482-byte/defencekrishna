"""Operator CLI for verified campaign manifests; records evidence, never invents labels."""
from __future__ import annotations

import argparse
from pathlib import Path

from .verified_campaigns import add_benign_interval, add_event, load_manifest, new_manifest, save_manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    q=sub.add_parser('init');q.add_argument('--output',required=True);q.add_argument('--campaign-id',required=True);q.add_argument('--role',required=True);q.add_argument('--domain',required=True);q.add_argument('--capture',required=True);q.add_argument('--graph-path',required=True);q.add_argument('--start-epoch',type=float,required=True);q.add_argument('--end-epoch',type=float,required=True);q.add_argument('--timezone',required=True);q.add_argument('--evidence',required=True)
    q=sub.add_parser('benign');q.add_argument('--manifest',required=True);q.add_argument('--start-epoch',type=float,required=True);q.add_argument('--end-epoch',type=float,required=True);q.add_argument('--evidence',required=True)
    q=sub.add_parser('event');q.add_argument('--manifest',required=True);q.add_argument('--event-id',required=True);q.add_argument('--epoch',type=float,required=True);q.add_argument('--stage',required=True);q.add_argument('--outcome',required=True);q.add_argument('--source-host');q.add_argument('--target-host');q.add_argument('--establishes-compromise',action='store_true');q.add_argument('--evidence',required=True)
    q=sub.add_parser('audit');q.add_argument('--manifest',required=True)
    a=p.parse_args()
    if a.cmd=='init':
        m=new_manifest(campaign_id=a.campaign_id,role=a.role,domain=a.domain,capture_path=a.capture,graph_path=a.graph_path,start_epoch=a.start_epoch,end_epoch=a.end_epoch,timezone=a.timezone,evidence_source=a.evidence);save_manifest(a.output,m,refuse_overwrite=True);print(a.output);return
    m=load_manifest(a.manifest)
    if a.cmd=='benign':m=add_benign_interval(m,a.start_epoch,a.end_epoch,a.evidence);save_manifest(a.manifest,m);print(a.manifest);return
    if a.cmd=='event':m=add_event(m,event_id=a.event_id,epoch=a.epoch,stage=a.stage,outcome=a.outcome,evidence=a.evidence,establishes_compromise=a.establishes_compromise,source_host=a.source_host,target_host=a.target_host);save_manifest(a.manifest,m);print(a.manifest);return
    if a.cmd=='audit':
        import json
        print(json.dumps(m,indent=2));return

if __name__=='__main__':main()
