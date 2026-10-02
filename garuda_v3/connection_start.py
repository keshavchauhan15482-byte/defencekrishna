"""First-packet connection-start graphs; no finished-session statistics as inputs.

Publisher conn logs reconstruct a retrospective first-packet event stream. A
logged record's export time remains unknown. This path does not claim that the
historical conn.log itself was delivered live at ts. A live sensor must emit
these fields when first observed and record receipt times separately.
"""
from __future__ import annotations

import csv
import ipaddress
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .causal_stage_forecast import native_label, sha, number, STAGES, HISTORY, HORIZON, STEP
from .data import SERVICE_NODES, PORTS
from .model import CONNECTION_START_SCHEMA

FEATURES = ['connection_count_log', 'tcp_start_fraction', 'udp_start_fraction',
    'icmp_start_fraction', 'minimum_endpoint_port_mean_scaled',
    'unique_minimum_endpoint_port_fraction', 'unique_endpoint_one_fraction',
    'unique_endpoint_two_fraction', 'start_iat_mean_log', 'start_iat_std_log',
    'sequential_minimum_port_fraction', 'random_minimum_port_fraction',
    'same_peer_start_fraction', 'ssh_start_fraction', 'dns_start_fraction',
    'web_start_fraction', 'smb_start_fraction', 'ftp_start_fraction', 'active']
NETWORK_COLUMNS = ['uid', 'ts', 'src_ip_zeek', 'dest_ip_zeek', 'src_port_zeek',
                   'dest_port_zeek', 'proto']


def event(row):
    if not isinstance(row.get('uid'),str) or not row['uid']:
        raise ValueError('Stable first-packet event identity required')
    t=number(row['ts']);proto=str(row['proto']).lower()
    if proto not in ('tcp','udp','icmp'):raise ValueError('Unsupported connection transport')
    def port(value):
        v=0 if proto=='icmp' and value is None else number(value)
        if v!=int(v) or v>65535:raise ValueError('Invalid endpoint port')
        return int(v)
    a=(str(ipaddress.ip_address(row['src_ip_zeek'])),port(row['src_port_zeek']))
    b=(str(ipaddress.ip_address(row['dest_ip_zeek'])),port(row['dest_port_zeek']))
    # Zeek may later flip originator/responder direction. Endpoint symmetry keeps
    # that future orientation decision out of first-packet feature semantics.
    a,b=sorted((a,b))
    return {'uid':row['uid'],'t':t,'proto':proto,'src':a[0],'dst':b[0],
            'sport':max(a[1],b[1]),'port':min(a[1],b[1])}


def summarize(events):
    n=len(events)
    ordered=sorted(events,key=lambda e:e['t'])
    iat=np.diff([e['t'] for e in ordered])
    # Equal timestamps do not establish an ordering of port accesses.
    pairs=[(a,b) for a,b in zip(ordered,ordered[1:])
           if a['t']<b['t'] and a['src']==b['src'] and a['dst']==b['dst']]
    jumps=[abs(a['port']-b['port']) for a,b in pairs]
    def scaled(value,maximum):return min(1.0,math.log1p(value)/math.log1p(maximum))
    return np.asarray([scaled(n,10000),
        *[sum(e['proto']==p for e in events)/n for p in ('tcp','udp','icmp')],
        sum(e['port'] for e in events)/(65535*n),len({e['port'] for e in events})/n,
        len({e['src'] for e in events})/n,len({e['dst'] for e in events})/n,
        scaled(float(iat.mean()) if len(iat) else 0,10),
        scaled(float(iat.std()) if len(iat) else 0,10),
        sum(v==1 for v in jumps)/max(1,len(jumps)),
        sum(v>1 for v in jumps)/max(1,len(jumps)),
        1-len({(e['src'],e['dst']) for e in events})/n,
        *[sum(e['port'] in ports for e in events)/n
          for ports in ((22,),(53,),(80,443,8080),(139,445),(20,21))],1],np.float32)


def graphs_from_rows(rows):
    unique={};audit=Counter();bad=set();label_cache={}
    for row in rows:
        audit['rows']+=1
        try:
            key=(row.get('uid'),number(row['ts']))
            signature=tuple(row.get(k) for k in NETWORK_COLUMNS[2:])
            previous=unique.get(key)
            e=previous[0] if previous is not None and previous[3]==signature else event(row)
        except (ValueError,TypeError,KeyError,OverflowError):
            try:bad.add(int(number(row['ts'])//STEP)*STEP)
            except (ValueError,TypeError,KeyError,OverflowError):
                raise ValueError('Malformed event has no bounded observation timestamp')
            audit['invalid_start_events']+=1;continue
        binary=str(row.get('label_binary','')).lower()
        label_key=(str(row.get('label_tactic')),binary)
        if label_key not in label_cache:
            risk,stage=native_label(row.get('label_tactic'))
            if (binary=='true' and risk==0) or (binary=='false' and risk==1):
                risk,stage=-1,np.full(5,-1,np.int8)
            label_cache[label_key]=(risk,stage)
        risk,stage=label_cache[label_key]
        if key in unique:
            original,r,s,signature=unique[key]
            if original!=e:raise ValueError('Conflicting first-packet event identity')
            if r<0 or risk<0 or (r==0)!=(risk==0):r,s=-1,np.full(5,-1,np.int8)
            elif s is not stage:s=np.maximum(s,stage)
            unique[key]=(e,r,s,signature);audit['duplicate_label_copies_merged']+=1
        else:unique[key]=(e,risk,stage,signature)
    groups=defaultdict(list)
    for e,r,s,_ in unique.values():groups[int(e['t']//STEP)*STEP].append((e,r,s))
    xs=[];adjs=[];masks=[];times=[];truth=[];stages=[];attack_times=[]
    for t,records in sorted(groups.items()):
        if t in bad:audit['contaminated_windows_removed']+=1;continue
        selected=defaultdict(list);adj=np.zeros((len(SERVICE_NODES),len(SERVICE_NODES)),np.float32)
        for e,r,s in records:
            pi={'tcp':0,'udp':1,'icmp':2}[e['proto']]
            si=3+PORTS.index(e['port']) if e['port'] in PORTS else len(SERVICE_NODES)-1
            selected[pi].append(e);selected[si].append(e);adj[pi,si]+=1
        x=np.zeros((len(SERVICE_NODES),len(FEATURES)),np.float32);mask=np.zeros(len(SERVICE_NODES),np.float32)
        for i,ev in selected.items():x[i]=summarize(ev);mask[i]=1
        labels=[r for e,r,s in records];unknown=any(r<0 for r in labels)
        y=1 if 1 in labels else (-1 if unknown else 0)
        s=np.asarray([1 if any(v[i]==1 for e,r,v in records)
            else (-1 if unknown else 0) for i in range(5)],np.int8)
        xs.append(x);adjs.append(adj);masks.append(mask);times.append(t);truth.append(y);stages.append(s)
        attack_times.append(min((e['t'] for e,r,s in records if r==1),default=np.nan))
    if len(times)<2:raise ValueError('No valid first-packet event windows')
    # Conservative boundary treatment; no unobserved empty bucket is labelled benign.
    stop=-1
    d={'x':np.asarray(xs[:stop]),'adj':np.asarray(adjs[:stop]),'mask':np.asarray(masks[:stop]),
       'times':np.asarray(times[:stop],np.int64),'y':np.asarray(truth[:stop],np.int8),
       'stage':np.asarray(stages[:stop],np.int8),'attack_times':np.asarray(attack_times[:stop])}
    audit=dict(audit)
    audit.update(unique_start_events=len(unique),observed_windows=len(d['times']),
        invalid_only_windows_removed=len(bad-set(groups)),
        contaminated_windows_removed=audit.get('contaminated_windows_removed',0),
        empty_windows_imputed=0,finished_flow_statistics_used=False,
        record_export_availability_certified=False,
        risk_window_counts={str(i):int((d['y']==i).sum()) for i in (-1,0,1)},
        native_stage_windows={s:int((d['stage'][:,i]==1).sum()) for i,s in enumerate(STAGES)})
    return d,dict(audit)


def source_rows(source,benign=None):
    import pyarrow.parquet as pq
    pf=pq.ParquetFile(source['path']);names=pf.schema_arrow.names
    if not set(NETWORK_COLUMNS+['label_tactic']).issubset(names):raise ValueError('Native first-packet source schema missing')
    columns=NETWORK_COLUMNS+['label_tactic']+(['label_binary'] if 'label_binary' in names else [])
    left,right=[datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp() for day in source['week'].split(' - ')]
    for batch in pf.iter_batches(batch_size=32768,columns=columns):
        for row in batch.to_pylist():
            if left<=number(row['ts'])<right:yield row
    if benign is not None:
        left,right=[datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp() for day in source['week'].split(' - ')]
        with Path(benign['path']).open(newline='',encoding='utf-8-sig') as f:
            reader=csv.DictReader(f)
            if not set(NETWORK_COLUMNS).issubset(reader.fieldnames or []):raise ValueError('Benign event schema missing')
            folder_label='label_tactic' not in reader.fieldnames
            if folder_label and (benign.get('annotation')!='publisher_benign_folder' or '/csv/Benign/' not in benign['url']):
                raise ValueError('Benign truth provenance required')
            for row in reader:
                row={k:row.get(k) for k in columns}
                row['ts']=number(row['ts'])
                if not left<=row['ts']<right:continue
                for k in ('src_port_zeek','dest_port_zeek'):
                    if row[k] in ('','-'):row[k]=None
                if folder_label:row['label_tactic']='none'
                if native_label(row['label_tactic'])[0]!=0:raise ValueError('Attack row in benign export')
                yield row


def prepare_source(source,benign=None,max_sequences=None,mmap_dir=None):
    if sha(source['path'])!=source['sha256']:raise ValueError('Event source hash changed')
    if benign and sha(benign['path'])!=benign['sha256']:raise ValueError('Benign source hash changed')
    d,audit=graphs_from_rows(source_rows(source,benign))
    # Sparse observations are explicitly UNKNOWN, not zero-traffic benign data.
    times=np.arange(d['times'][0],d['times'][-1]+STEP,STEP,dtype=np.int64)
    positions=np.searchsorted(times,d['times']);observed=np.zeros(len(times),bool);observed[positions]=True
    dense={}
    for k in ('x','adj','mask','y','stage','attack_times'):
        fill=-1 if k in ('y','stage') else (np.nan if k=='attack_times' else 0)
        dense[k]=np.full((len(times),*d[k].shape[1:]),fill,dtype=d[k].dtype);dense[k][positions]=d[k]
    d={**dense,'times':times}
    starts=[s for s in range(len(times)-HISTORY-HORIZON+1)
        if observed[s+HISTORY-1] and observed[s:s+HISTORY].sum()>=4
        and observed[s+HISTORY:s+HISTORY+HORIZON].any()]
    available=len(starts)
    if max_sequences and available>max_sequences:starts=starts[::math.ceil(available/max_sequences)]
    audit.update(id=source['id'],sha256=source['sha256'],sequences=len(starts),available_sequences=available)
    if not starts:return None,audit
    pooled=(d['x']*d['mask'][...,None]).sum(1)/np.maximum(d['mask'].sum(1,keepdims=True),1)
    out={}
    for k in ('x','adj','mask'):
        if mmap_dir is None:out[k]=np.stack([d[k][s:s+HISTORY] for s in starts])
        else:
            folder=Path(mmap_dir);folder.mkdir(parents=True,exist_ok=True)
            out[k]=np.lib.format.open_memmap(folder/(k+'.npy'),mode='w+',dtype=d[k].dtype,
                shape=(len(starts),HISTORY,*d[k].shape[1:]))
            for offset in range(0,len(starts),256):
                part=starts[offset:offset+256]
                out[k][offset:offset+len(part)]=np.stack([d[k][s:s+HISTORY] for s in part])
            out[k].flush()
    out.update(future=np.stack([pooled[s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        future_observed=np.stack([observed[s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        y=np.stack([d['y'][s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        stage=np.stack([d['stage'][s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        history_y=np.stack([d['y'][s:s+HISTORY] for s in starts]),
        history_stage=np.stack([d['stage'][s:s+HISTORY] for s in starts]),
        future_attack_times=np.stack([d['attack_times'][s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        cutoff=np.asarray([d['times'][s+HISTORY-1]+STEP for s in starts],np.int64))
    out['day']=out['cutoff']//86400;out['source']=np.full(len(starts),source['id'])
    audit.update(future_risk_counts={str(i):int((out['y']==i).sum()) for i in (-1,0,1)},
        missing_observation_buckets=int((~observed).sum()),
        minimum_observed_history_windows=4,origin_window_must_be_observed=True,
        future_state_observed_fraction=float(out['future_observed'].mean()),
        clean_future_positive_sequences=int(((out['history_y']==0).all(1)&(out['y']==1).any(1)).sum()))
    return out,audit
