"""AIT completed-flow development graphs; no invented packet or MITRE truth."""
import argparse
from collections import defaultdict
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import re
import urllib.request
import zipfile
import numpy as np
from .ait_source_audit import DEVELOPMENT
from .data import FEATURES, SCHEMA, graph_snapshot, save_dataset


def label_contract(raw):
    if hashlib.md5(raw).hexdigest() != 'e32c0e08d15725999df0c6a0c02aff47':
        raise ValueError('Publisher label contract checksum mismatch')
    labels={};current=None
    for line in raw.decode().splitlines():
        line=line.strip()
        if not line: continue
        if line.startswith('Benign labels in '): current=0;continue
        if line.startswith('Malicious labels in '): current=1;continue
        if current is None: raise ValueError('Label section missing')
        if line in labels and labels[line]!=current: raise ValueError('Conflicting publisher labels')
        labels[line]=current
    return labels


def normalized(row):
    return {re.sub(r'^\d+#','',k.split(':')[0].lstrip('#')):v for k,v in row.items() if k is not None}


def value(row,key,default=None):
    text=row.get(key)
    if text in (None,'','-'):
        if default is None: raise ValueError('Missing '+key)
        return default
    n=float(text)
    if not math.isfinite(n) or n<0: raise ValueError('Invalid '+key)
    return n


def flow(raw,protocol,labels):
    r=normalized(raw)
    if protocol=='tcp':
        start,end=value(r,'first')/1000,value(r,'last')/1000
        flags=[value(r,'c_'+k+'_cnt',0)+value(r,'s_'+k+'_cnt',0) for k in ('syn','ack','rst','fin')]
    else:
        start=value(r,'c_first_abs')/1000
        end=max(start+value(r,'c_durat')/1000,
                value(r,'s_first_abs',0)/1000+value(r,'s_durat',0)/1000)
        flags=[0]*4
    if start<1e9 or end<start: raise ValueError('Invalid completed-flow UTC epoch')
    port=value(r,'s_port')
    if port!=int(port) or port>65535: raise ValueError('Invalid destination port')
    return dict(start=start,end=end,duration=end-start,
        packets=value(r,'c_pkts_all')+value(r,'s_pkts_all'),
        bwd=value(r,'s_pkts_all'),bytes=value(r,'c_bytes_all')+value(r,'s_bytes_all'),
        protocol=protocol,port=int(port),flags=flags,src=r['c_ip'],dst=r['s_ip'],
        label=labels.get(r.get('label','').strip()),iat_ms=None,tcp_window=0,
        window_present=False,packet_present=False)


def convert(campaign,cache,output):
    cache,output=Path(cache),Path(output)
    if output.exists(): raise ValueError('Graph output must be new')
    if campaign not in DEVELOPMENT: raise ValueError('Only declared development sources allowed')
    archive=cache/(campaign+'_netflows.zip')
    digest=hashlib.md5(archive.read_bytes()).hexdigest()
    if digest!=DEVELOPMENT[campaign]: raise ValueError('Source checksum mismatch')
    contract=cache/'label_info.txt'
    if not contract.exists():
        with urllib.request.urlopen('https://zenodo.org/api/records/13168643/files/label_info.txt/content',timeout=25) as r:
            raw=r.read(4096)
        label_contract(raw)
        with contract.open('xb') as f:f.write(raw)
    labels=label_contract(contract.read_bytes())
    groups=defaultdict(list);rows=0
    with zipfile.ZipFile(archive) as z:
        for name in ('tcp_complete.csv','tcp_nocomplete.csv','udp_complete.csv'):
            with z.open(name) as f:
                for row in csv.DictReader(io.TextIOWrapper(f,encoding='utf-8-sig')):
                    item=flow(row,'udp' if name.startswith('udp') else 'tcp',labels)
                    groups[int(item['end']//10)*10].append(item);rows+=1
    xs,adjs,masks,ys,times=[],[],[],[],[]
    for t,flows in sorted(groups.items()):
        x,a,m,_=graph_snapshot(flows,'service',32)
        truth=[f['label'] for f in flows]
        xs.append(x);adjs.append(a);masks.append(m);times.append(t)
        ys.append(1 if 1 in truth else -1 if None in truth else 0)
    meta=dict(schema=SCHEMA,features=FEATURES,mode='service',window_seconds=10,max_nodes=32,
        campaign_id='AIT-'+campaign,source_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        dataset_id='AIT-Netflow-v2',packet_features=False,synthetic=True,
        timestamp_semantics='completed-flow end UTC; no finished-session features at flow start',
        graph_scope='protocol-service, not host topology',risk_target='future malicious completed-flow presence',
        stage_labels_available=False,compromise_labels_available=False,
        unavailable_features='IAT, window, TTL/variance, fragments and retransmissions not exported into this 21-feature diagnostic',
        publisher_label_contract_md5=hashlib.md5(contract.read_bytes()).hexdigest())
    data=dict(x=np.asarray(xs),adj=np.asarray(adjs),mask=np.asarray(masks),y=np.asarray(ys,dtype=np.int8),times=np.asarray(times,dtype=np.int64),metadata=meta)
    save_dataset(data,output)
    return dict(campaign=campaign,raw_records=rows,observed_windows=len(times),
        positive_windows=int((data['y']==1).sum()),negative_windows=int((data['y']==0).sum()),unknown_windows=int((data['y']<0).sum()),source_sha256=meta['source_sha256'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',required=True);p.add_argument('--cache',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();print(json.dumps(convert(a.campaign,a.cache,a.output),indent=2))


if __name__=='__main__':main()
