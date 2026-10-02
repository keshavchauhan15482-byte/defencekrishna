"""Native-label future-state/risk/tactic experiment on complete UWF flow shards.

This research path indexes records at an explicit receipt timestamp, or at a
declared earliest-session-end proxy when no receipts exist. The latter cannot
establish causal live availability. Labels are targets only. It does not invent packet features, rename
Discovery to Reconnaissance, or equate a malicious flow with compromise. The
production packet checkpoint and its containment gates remain unchanged.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .autograd import Adam
from .data import PORTS, SERVICE_NODES
from .model import CAUSAL_FLOW_SCHEMA, GraphWorldModel

STAGES = ['Reconnaissance', 'Initial Access', 'Lateral Movement', 'Command and Control', 'Exfiltration']
FEATURES = ['completed_flow_count_log', 'orig_packets_log', 'resp_packets_log',
            'ip_bytes_log', 'mean_duration_ms_log', 'backward_packet_fraction',
            'tcp_flow_fraction', 'udp_flow_fraction', 'unique_destination_ports_log',
            'unique_peer_count_log', 'origin_byte_fraction', 'active',
            'destination_port_mean_scaled', 'ssh_flow_fraction', 'dns_flow_fraction',
            'web_flow_fraction', 'smb_flow_fraction', 'rdp_flow_fraction', 'ftp_flow_fraction']
HISTORY, HORIZON, STEP = 8, 4, 10
HEADS = {'risk', 'risk_b', 'stage', 'stage_b'}
COLUMNS = ['ts', 'duration', 'proto', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes',
           'resp_ip_bytes', 'src_port_zeek', 'dest_port_zeek', 'src_ip_zeek', 'dest_ip_zeek', 'uid', 'label_tactic']
NATIVE_TACTICS = {s.lower() for s in STAGES} | {'resource development', 'execution',
    'persistence', 'privilege escalation', 'defense evasion', 'credential access',
    'discovery', 'collection', 'impact'}


def flatten_labels(value):
    if isinstance(value,(list,tuple)):
        return [label for item in value for label in flatten_labels(item)]
    if not isinstance(value,str):return []
    parts=re.split(r'\s*[,;|]\s*',value.strip('[]{}()'))
    return [re.sub(r'\s+',' ',p.strip(" '\"").replace('_',' ').replace('-',' ')).lower().replace('command & control','command and control') for p in parts if p.strip(" '\"")]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def native_label(value):
    """Preserve publisher multi-tactic annotations and missing-label uncertainty."""
    if value is None or str(value).strip().lower() in ('', 'null', 'nan', '[]'):
        return -1, np.full(5, -1, np.int8)
    if str(value).strip().lower() == 'none':
        return 0, np.zeros(5, np.int8)
    labels = flatten_labels(value)
    if labels == ['none']:
        return 0, np.zeros(5, np.int8)
    if not labels or 'none' in labels or any(s not in NATIVE_TACTICS for s in labels):
        return -1, np.full(5, -1, np.int8)
    # Non-PS native tactics are still attacks; none is renamed to a PS tactic.
    return 1, np.asarray([int(s.lower() in labels) for s in STAGES], np.int8)


def number(v):
    n = float(v)
    if not math.isfinite(n) or n < 0: raise ValueError('Invalid nonnegative telemetry')
    return n


def completed_flow(row):
    start = number(row['ts'])
    op, rp = number(row['orig_pkts']), number(row['resp_pkts'])
    duration = row['duration']
    if duration is None or str(duration).strip() in ('', '-'):
        if op + rp != 1: raise ValueError('Unknown multi-packet completion time')
        duration = 0.0  # A one-packet record has no unobserved session duration.
    duration = number(duration)
    proto = str(row['proto']).lower()
    port = 0 if proto not in ('tcp','udp') and row['dest_port_zeek'] is None else number(row['dest_port_zeek'])
    if port != int(port) or port > 65535: raise ValueError('Invalid destination port')
    end=start+duration
    received=row.get('_record_available_at')
    if received is not None and number(received)<end:raise ValueError('Receipt precedes observed session span')
    return {'start': start, 'end': end, 'available':number(received) if received is not None else end, 'duration': duration,
            'op': op, 'rp': rp, 'ob': number(row['orig_ip_bytes']),
            'rb': number(row['resp_ip_bytes']), 'port': int(port),
            'proto': proto, 'src': str(row['src_ip_zeek']),
            'dst': str(row['dest_ip_zeek'])}


def summarize(flows):
    n = len(flows)
    op, rp = sum(f['op'] for f in flows), sum(f['rp'] for f in flows)
    ob, rb = sum(f['ob'] for f in flows), sum(f['rb'] for f in flows)
    def scaled(value, scale): return min(1.0, math.log1p(value) / math.log1p(scale))
    return np.asarray([scaled(n, 10000), scaled(op, 1e7), scaled(rp, 1e7),
        scaled(ob + rb, 1e9), scaled(sum(f['duration'] for f in flows)*1000/n, 1e7),
        rp/max(1, op+rp), sum(f['proto']=='tcp' for f in flows)/n,
        sum(f['proto']=='udp' for f in flows)/n,
        scaled(len({f['port'] for f in flows}), 65535),
        scaled(len({f[k] for f in flows for k in ('src','dst')}), 100000),
        ob/max(1, ob+rb), 1.0, sum(f['port'] for f in flows)/(n*65535),
        sum(f['port']==22 for f in flows)/n, sum(f['port']==53 for f in flows)/n,
        sum(f['port'] in (80,443,8080) for f in flows)/n,
        sum(f['port'] in (139,445) for f in flows)/n,
        sum(f['port']==3389 for f in flows)/n, sum(f['port'] in (20,21) for f in flows)/n], np.float32)


def graphs_from_rows(rows):
    groups, truth, contaminated = {}, {}, set()
    censored_after = None
    audit = Counter(); labels = Counter()
    # UWF flattens overlapping native tactics into duplicate copies of one flow.
    # Merge their labels before aggregation; count its bytes/packets exactly once.
    unique = {}
    for row in rows:
        audit['rows'] += 1
        key = tuple(row.get(k) for k in ('uid','ts','src_ip_zeek','dest_ip_zeek','src_port_zeek','dest_port_zeek','proto'))
        if not row.get('uid'): raise ValueError('Stable publisher flow identity required for deduplication')
        if key not in unique:
            unique[key] = (row, [row.get('label_tactic')])
        else:
            existing, native = unique[key]
            if any(existing.get(k) != row.get(k) for k in COLUMNS if k != 'label_tactic'):
                raise ValueError('Conflicting telemetry for duplicate flow identity')
            native.append(row.get('label_tactic')); audit['flattened_duplicate_rows_merged'] += 1
    for row, native in unique.values():
        try:
            f = completed_flow(row)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            if 'Unknown multi-packet completion time' in str(exc):
                boundary = int(number(row['ts']) // STEP) * STEP
                censored_after = boundary if censored_after is None else min(boundary,censored_after)
                audit['unbounded_completion_rows'] += 1
                continue
            audit['invalid_rows'] += 1
            # The invalid record can make neither benign truth nor state evidence.
            try:
                end = number(row['ts']) + number(row['duration'])
                contaminated.add(int(end // STEP) * STEP)
            except (ValueError, TypeError, KeyError): pass
            continue
        bucket = int(f['available'] // STEP) * STEP
        groups.setdefault(bucket, []).append(f)
        individual = [native_label(v) for v in native]
        known = {v[0] for v in individual if v[0] >= 0}
        if known == {0,1}: y,stage = -1,np.full(5,-1,np.int8)
        else:
            y = 1 if 1 in known else (-1 if any(v[0]<0 for v in individual) else 0)
            stage = np.asarray([1 if any(v[1][i]==1 for v in individual) else
                (-1 if any(v[1][i]<0 for v in individual) else 0) for i in range(5)],np.int8)
        truth.setdefault(bucket, []).append((y, stage))
        for v in set(map(str,native)): labels[v] += 1
    xs, adjs, masks, ys, stages, times = [], [], [], [], [], []
    mapping = {name: i for i, name in enumerate(SERVICE_NODES)}
    for bucket, flows in sorted(groups.items()):
        if censored_after is not None and bucket >= censored_after:
            audit['windows_censored_after_unknown_completion'] += 1
            continue
        if bucket in contaminated:
            audit['contaminated_windows_removed'] += 1
            continue
        local = {}; a = np.zeros((len(mapping), len(mapping)), np.float32)
        for f in flows:
            proto = f['proto'] if f['proto'] in ('tcp','udp') else 'other'
            src = mapping['protocol:'+proto]
            dst = mapping['service:'+str(f['port'])] if f['port'] in PORTS else mapping['service:other']
            local.setdefault(src, []).append(f); local.setdefault(dst, []).append(f)
            a[dst, src] += 1
        x = np.zeros((len(mapping), len(FEATURES)), np.float32)
        m = np.zeros(len(mapping), np.float32)
        for node, node_flows in local.items(): x[node], m[node] = summarize(node_flows), 1
        # Adjacency is a count; GraphSAGE normalizes it independently in each state.
        labs = truth[bucket]
        y = 1 if any(v[0] == 1 for v in labs) else (-1 if any(v[0] < 0 for v in labs) else 0)
        sy = np.asarray([1 if any(v[1][i] == 1 for v in labs) else
                         (-1 if any(v[1][i] < 0 for v in labs) else 0) for i in range(5)], np.int8)
        xs.append(x); adjs.append(a); masks.append(m); ys.append(y); stages.append(sy); times.append(bucket)
    if not times: raise ValueError('No valid completed-flow windows after unknown-completion censoring')
    # Reject the last observed bucket: capture/export completeness is unverified.
    d = {'x': np.asarray(xs[:-1]), 'adj': np.asarray(adjs[:-1]), 'mask': np.asarray(masks[:-1]),
         'y': np.asarray(ys[:-1]), 'stage': np.asarray(stages[:-1]), 'times': np.asarray(times[:-1], np.int64)}
    audit['windows'] = len(d['times']); audit['unique_flows'] = len(unique)
    return d, {**dict(audit), 'native_label_counts': dict(labels),
        'packet_features_available': False, 'host_topology_claim': False,
        'availability': 'explicit record receipts when supplied; otherwise unverified ts+duration proxy',
        'unknown_labels_preserved': True, 'partial_terminal_window_dropped': True}


def benign_rows(source, benign):
    left = datetime.fromisoformat(source['week'].split(' - ')[0]).replace(tzinfo=timezone.utc).timestamp()
    right = datetime.fromisoformat(source['week'].split(' - ')[1]).replace(tzinfo=timezone.utc).timestamp()
    with Path(benign['path']).open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        if not (set(COLUMNS)-{'label_tactic'}).issubset(reader.fieldnames or []):raise ValueError('Benign network schema mismatch')
        folder_label = 'label_tactic' not in (reader.fieldnames or [])
        if folder_label and (benign.get('annotation')!='publisher_benign_folder' or '/csv/Benign/' not in benign['url']):
            raise ValueError('Missing benign truth provenance')
        for row in reader:
            if folder_label:row['label_tactic']='none'
            for k in ('ts','duration','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','src_port_zeek','dest_port_zeek'):
                row[k]=None if row[k].strip() in ('','-') else float(row[k])
            end=number(row['ts'])+(number(row['duration']) if row['duration'] is not None else 0)
            if not left <= end < right:continue
            if native_label(row['label_tactic'])[0]!=0:raise ValueError('Non-benign row in publisher benign source')
            yield row


def prepare_source(source, benign=None, max_sequences=None):
    import pyarrow.parquet as pq
    pf = pq.ParquetFile(source['path'])
    if not set(COLUMNS).issubset(pf.schema_arrow.names): raise ValueError('Required native network columns missing')
    receipts=None
    if source.get('availability_receipts_path'):
        path=Path(source['availability_receipts_path'])
        if sha(path)!=source.get('availability_receipts_sha256'):raise ValueError('Receipt provenance hash mismatch')
        receipts={}
        for line in path.read_text().splitlines():
            r=json.loads(line);key=(str(r['uid']),number(r['first_packet_ts']))
            if key in receipts:raise ValueError('Duplicate receipt identity')
            receipts[key]=number(r['received_at_utc_epoch'])
    def rows():
        def available(row):
            if receipts is not None:
                key=(str(row['uid']),number(row['ts']))
                if key not in receipts:raise ValueError('Missing source-verified record receipt')
                row['_record_available_at']=receipts[key]
            return row
        for b in pf.iter_batches(batch_size=32768, columns=COLUMNS):
            for row in b.to_pylist():yield available(row)
        if benign is not None:
            for row in benign_rows(source,benign):yield available(row)
    d, audit = graphs_from_rows(rows())
    starts = [s for s in range(len(d['times']) - HISTORY - HORIZON + 1)
              if np.all(np.diff(d['times'][s:s+HISTORY+HORIZON]) == STEP)]
    if not starts:
        return None, {'id':source['id'],'sha256':source['sha256'],**audit,
            'sequences':0,'quality_excluded':'No contiguous 80s+40s complete observations'}
    available_sequences = len(starts)
    if max_sequences and len(starts)>max_sequences:
        starts=starts[::math.ceil(len(starts)/max_sequences)]
    pooled = (d['x'] * d['mask'][..., None]).sum(1) / np.maximum(d['mask'].sum(1, keepdims=True), 1)
    out = {k: np.stack([d[k][s:s+HISTORY] for s in starts]) for k in ('x','adj','mask')}
    out.update(future=np.stack([pooled[s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        y=np.stack([d['y'][s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        stage=np.stack([d['stage'][s+HISTORY:s+HISTORY+HORIZON] for s in starts]),
        history_y=np.stack([d['y'][s:s+HISTORY] for s in starts]),
        cutoff=np.asarray([d['times'][s+HISTORY-1]+STEP for s in starts], np.int64))
    out['day'] = out['cutoff'] // 86400
    out['source'] = np.full(len(starts), source['id'])
    audit.update(sequences=len(starts), available_sequences=available_sequences,
        record_availability_certified=receipts is not None, observed_days=len(np.unique(out['day'])),
        future_risk_counts={str(v): int((out['y']==v).sum()) for v in (-1,0,1)},
        future_native_stage_support={s:int((out['stage'][...,i]==1).sum()) for i,s in enumerate(STAGES)})
    return out, {'id':source['id'], 'release':source['release'], 'week':source['week'],
                 'sha256':source['sha256'], 'benign_source_sha256':benign['sha256'] if benign else None, **audit}


def acquire(protocol, root):
    root.mkdir(parents=True, exist_ok=True)
    result = []
    for s in protocol['sources']+protocol.get('benign_sources',[]):
        extension='.csv' if s.get('role')=='time_matched_benign' else '.parquet'
        path = root/(s['id']+extension)
        if not path.exists():
            tmp = path.with_suffix('.download')
            with urllib.request.urlopen(urllib.request.Request(s['url'], headers={'User-Agent':'Garuda-causal-native/1.0'}), timeout=120) as r, tmp.open('wb') as f:
                while b := r.read(1 << 20): f.write(b)
            if tmp.stat().st_size != s['expected_bytes']: raise ValueError('Publisher size mismatch')
            tmp.replace(path)
        if path.stat().st_size != s['expected_bytes']: raise ValueError('Cached source size mismatch')
        digest = sha(path)
        if s.get('sha256') and digest != s['sha256']: raise ValueError('Pinned source hash mismatch')
        result.append({**s, 'path':str(path), 'sha256':digest})
    return result


def validate_protocol(p):
    if p['schema'] != 'garuda-causal-native-protocol-1' or p['frozen_before_test_metrics'] is not True:
        raise ValueError('Frozen scientific protocol required')
    if (p['window_seconds'],p['history'],p['horizon']) != (STEP,HISTORY,HORIZON): raise ValueError('Time contract mismatch')
    if len(set(p['seeds'])) < 3: raise ValueError('At least three fixed seeds required')
    sources = p['sources']; ids = [s['id'] for s in sources]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate source across splits')
    dev = {s['release'] for s in sources if s['split'] in ('train','validation')}
    final = {s['release'] for s in sources if s['split']=='test'}
    if not final or final & dev: raise ValueError('Independent final dataset release required')
    if any(s['split'] not in ('train','validation','test') for s in sources): raise ValueError('Unknown split')
    seen={}
    for s in sources+p.get('benign_sources',[]):
        if not s.get('url','').startswith('https://datasets.uwf.edu/data/') or not re.fullmatch('[a-f0-9]{64}',s.get('sha256','')):
            raise ValueError('Hash-pinned publisher URLs required')
        group='test' if s['release'] in final else 'development'
        if s['sha256'] in seen and seen[s['sha256']]!=group:raise ValueError('Raw source alias leakage')
        seen[s['sha256']]=group


def load_group(sources, split, max_sequences=None, allow_empty=False):
    arrays, audits = [], []
    for s in sources:
        if s.get('split') != split: continue
        benign=next((b for b in sources if b.get('role')=='time_matched_benign' and b['release']==s['release']),None)
        try:d,a=prepare_source(s,benign,max_sequences)
        except ValueError as e:
            if not str(e).startswith('No valid completed-flow windows'):raise
            d,a=None,{'id':s['id'],'sha256':s['sha256'],'sequences':0,'quality_excluded':str(e)}
        audits.append(a)
        if d is not None:arrays.append(d)
        print(json.dumps({'prepared':s['id'],'split':split,'sequences':a['sequences']}), flush=True)
    if not arrays:
        if allow_empty:return None,audits
        raise ValueError('Empty '+split)
    return {k:np.concatenate([d[k] for d in arrays]) for k in arrays[0]}, audits


def predict(model, d, batch_size=128):
    outputs = [[] for _ in range(4)]
    for start in range(0, len(d['x']), batch_size):
        sl = slice(start,start+batch_size)
        for out, value in zip(outputs, model.forward(d['x'][sl], d['adj'][sl], d['mask'][sl], HORIZON, return_stages=True)):
            out.append(value.data)
    return tuple(np.concatenate(o) for o in outputs)


def state_objective(model, d, ids):
    mean, sigma, _ = model.forward(d['x'][ids], d['adj'][ids], d['mask'][ids], HORIZON)
    error = mean-d['future'][ids]
    if 'future_observed' not in d:
        return 10*error.power(2).mean() + .01*((error/sigma).power(2)*.5 + sigma.log()).mean()
    known=d['future_observed'][ids].astype(np.float32)
    denominator=np.maximum(known.sum(1),1)
    mse=((error.power(2).sum(2)/model.f)*known).sum(1)/denominator
    nll=((((error/sigma).power(2)*.5+sigma.log()).sum(2)/model.f)*known).sum(1)/denominator
    return 10*mse.mean()+.01*nll.mean()


def head_objective(model, d, ids, stage_supported):
    _, _, risk, stage = model.forward(d['x'][ids],d['adj'][ids],d['mask'][ids],HORIZON,return_stages=True)
    risk = .000001 + .999998*risk; stage = .000001 + .999998*stage
    y, sy = d['y'][ids], d['stage'][ids]
    known = (y>=0).astype(np.float32); target = np.maximum(y,0)
    bce = -((target*risk.log()+(1-target)*(1-risk).log())*known).sum()/max(1,known.sum())
    valid = ((sy>=0) & stage_supported).astype(np.float32); target = np.maximum(sy,0)
    # No oversampling; a small per-class weight is fixed on train data only.
    pos = (d['stage']==1).sum((0,1)); neg = (d['stage']==0).sum((0,1))
    weight = np.clip(np.sqrt(neg/np.maximum(pos,1)),1,3).astype(np.float32)
    stage_bce = -((weight*target*stage.log()+(1-target)*(1-stage).log())*valid).sum()/max(1,valid.sum())
    return bce+stage_bce


def binary_metrics(y, scores, threshold):
    keep = y>=0; y, scores = y[keep], scores[keep]
    positive, negative, pred = y==1, y==0, scores>=threshold
    tp, fp = int((pred & positive).sum()), int((pred & negative).sum())
    p, n = int(positive.sum()), int(negative.sum())
    pre = tp/(tp+fp) if tp+fp else None
    rec = tp/p if p else None
    fpr = fp/n if n else None
    def interval(k, count):
        if not count: return None
        z=1.96; a=k/count; den=1+z*z/count
        centre=(a+z*z/(2*count))/den; radius=z*math.sqrt(a*(1-a)/count+z*z/(4*count*count))/den
        return [max(0,centre-radius),min(1,centre+radius)]
    return {'positive_support':p,'negative_support':n,'unknown_support':int((~keep).sum()),
        'tp':tp,'fp':fp,'fn':p-tp,'tn':n-fp,'precision':pre,'recall':rec,'fpr':fpr,
        'f1':2*tp/max(1,2*tp+fp+(p-tp)) if p else None, 'recall_wilson_95':interval(tp,p),
        'fpr_wilson_95':interval(fp,n),
        'attack_performance_status':'MEASURABLE' if p else 'NO_FUTURE_POSITIVE_SUPPORT',
        'gate_passed':p>=30 and n>=300 and rec>=.8 and fpr<=.01}


def threshold(y, score):
    if int((y==0).sum()) < 300 or int((y==1).sum()) < 30:
        return 1.000001, 'INSUFFICIENT_VALIDATION_SUPPORT'
    negatives = np.sort(score[y==0]); allowed = int(len(negatives)*.01)
    t = float(np.nextafter(negatives[-allowed-1], np.inf))
    return t, 'VALIDATION_ONLY_1_PERCENT_FPR'


def fit_calibration(y, score):
    from sklearn.linear_model import LogisticRegression
    known=y>=0; y,score=y[known],score[known]
    if min(int((y==0).sum()),int((y==1).sum())) < 30:
        return {'status':'UNSUPPORTED','a':1.0,'b':0.0}
    logit=np.log(np.clip(score,1e-6,1-1e-6)/np.clip(1-score,1e-6,1-1e-6))
    m=LogisticRegression(C=1,random_state=42,max_iter=1000).fit(logit[:,None],y)
    return {'status':'VALIDATION_ONLY_PLATT','a':float(m.coef_[0,0]),'b':float(m.intercept_[0])}


def calibrate(score, cfg):
    logit=np.log(np.clip(score,1e-6,1-1e-6)/np.clip(1-score,1e-6,1-1e-6))
    return np.exp(-np.logaddexp(0,-(cfg['a']*logit+cfg['b'])))


def brier(y, score):
    k=y>=0
    return float(np.mean((score[k]-y[k])**2)) if k.any() else None


def state_metrics(d, mean):
    pooled=(d['x']*d['mask'][...,None]).sum(2)/np.maximum(d['mask'].sum(2,keepdims=True),1)
    known=d.get('future_observed',np.ones(d['future'].shape[:2],bool))
    if 'future_observed' not in d:
        pred_error=((mean-d['future'])**2).mean((1,2))
        base_error=((pooled[:,-1,None,:]-d['future'])**2).mean((1,2))
        horizon_mse=((mean-d['future'])**2).mean((0,2))
    else:
        if not known.any(1).all():raise ValueError('Every forecast needs an observed future state target')
        denominator=np.maximum(known.sum(1),1)
        pred_error=(((mean-d['future'])**2).mean(2)*known).sum(1)/denominator
        base_error=(((pooled[:,-1,None,:]-d['future'])**2).mean(2)*known).sum(1)/denominator
        horizon_mse=(((mean-d['future'])**2).mean(2)*known).sum(0)/np.maximum(known.sum(0),1)
    groups=np.unique(np.char.add(d['source'].astype(str),d['day'].astype(str)))
    identity=np.char.add(d['source'].astype(str),d['day'].astype(str))
    stats=[(pred_error[identity==g].sum(),base_error[identity==g].sum(),int((identity==g).sum())) for g in groups]
    rng=np.random.default_rng(20261001); boot=[]
    if len(groups)>=3:
        for _ in range(500):
            sampled=[stats[i] for i in rng.integers(0,len(groups),len(groups))]
            pe,be,_=np.sum(sampled,axis=0); boot.append(float((be-pe)/max(1e-12,be)))
    improvement=float(1-pred_error.mean()/max(1e-12,base_error.mean()))
    ci=np.quantile(boot,[.025,.975]).tolist() if boot else None
    return {'mse':float(pred_error.mean()),'persistence_mse':float(base_error.mean()),
        'relative_improvement':improvement,'paired_source_day_bootstrap_95':ci,
        'source_days':len(groups),'sequences':len(pred_error),
        'per_horizon_mse':[float(v) if known[:,h].any() else None for h,v in enumerate(horizon_mse)],
        'gate_passed':improvement>0 and ci is not None and ci[0]>0}


def train_candidate(arch, seed, train, val, p, out, *, feature_names=None, model_schema=CAUSAL_FLOW_SCHEMA):
    feature_names=FEATURES if feature_names is None else list(feature_names)
    if len(feature_names)!=train['x'].shape[-1] or len(set(feature_names))!=len(feature_names):
        raise ValueError('Explicit unique training feature identity required')
    model=GraphWorldModel(architecture=arch,feature_dim=len(feature_names),graph_dim=p['graph_dim'],
        hidden=p['hidden'],seed=seed,decoder='residual',stage_count=5,schema=model_schema)
    ids=np.arange(len(train['x']))
    if len(ids)>p['max_train_sequences']: ids=ids[::math.ceil(len(ids)/p['max_train_sequences'])]
    rng=np.random.default_rng(seed); batch=p['batch_size']
    pooled=(val['x']*val['mask'][...,None]).sum(2)/np.maximum(val['mask'].sum(2,keepdims=True),1)
    best=(state_metrics(val,np.repeat(pooled[:,-1,None,:],HORIZON,axis=1))['mse']
        if 'future_observed' in val else float(np.mean((pooled[:,-1,None,:]-val['future'])**2)))
    selected=None; state_logs=[]
    state_params=[v for k,v in model.params.items() if k not in HEADS]
    for k,v in model.params.items(): v.requires_grad=k not in HEADS
    opt=Adam(state_params,lr=.001)
    initial={k:v.data.copy() for k,v in model.params.items()}
    for epoch in range(p['state_epochs']):
        order=rng.permutation(ids)
        for start in range(0,len(order),batch): state_objective(model,train,order[start:start+batch]).backward();opt.step()
        mean,_,_,_=predict(model,val,batch)
        mse=state_metrics(val,mean)['mse'] if 'future_observed' in val else float(np.mean((mean-val['future'])**2))
        state_logs.append(mse)
        if mse<best: best=mse;selected={k:v.data.copy() for k,v in model.params.items()}
        print(json.dumps({'arch':arch,'seed':seed,'state_epoch':epoch+1,'validation_mse':mse}),flush=True)
    for k,v in (selected or initial).items(): model.params[k].data=v.copy()
    frozen={k:v.data.copy() for k,v in model.params.items() if k not in HEADS}
    supported=np.asarray([int((train['stage'][ids,...,i]==1).sum())>=5 and int((val['stage'][...,i]==1).sum())>=5 for i in range(5)])
    for k,v in model.params.items(): v.requires_grad=k in HEADS
    opt=Adam([model.params[k] for k in HEADS],lr=.003); best_loss=float('inf'); head_choice=None
    for epoch in range(p['head_epochs']):
        order=rng.permutation(ids)
        for start in range(0,len(order),batch): head_objective(model,train,order[start:start+batch],supported).backward();opt.step()
        _,_,risk,stage=predict(model,val,batch)
        valid=val['y']>=0; y=np.maximum(val['y'],0); r=np.clip(risk,1e-6,1-1e-6)
        v=float(-((y*np.log(r)+(1-y)*np.log(1-r))*valid).sum()/max(1,valid.sum()))
        sk=(val['stage']>=0)&supported;sy=np.maximum(val['stage'],0);ss=np.clip(stage,1e-6,1-1e-6)
        v+=float(-((sy*np.log(ss)+(1-sy)*np.log(1-ss))*sk).sum()/max(1,sk.sum()))
        if v<best_loss:best_loss=v;head_choice={k:model.params[k].data.copy() for k in HEADS}
    for k,v in head_choice.items():model.params[k].data=v
    if any(not np.array_equal(v,model.params[k].data) for k,v in frozen.items()):raise RuntimeError('Heads changed state backbone')
    _,_,vr,vs=predict(model,val,batch); calibration=[]; thresholds=[]; threshold_status=[]
    for h in range(HORIZON):
        cfg=fit_calibration(val['y'][:,h],vr[:,h]); calibration.append(cfg)
        t,status=threshold(val['y'][:,h],calibrate(vr[:,h],cfg));thresholds.append(t);threshold_status.append(status)
    stage_thresholds=[]
    for i in range(5):
        if not supported[i]:stage_thresholds.append(1.000001);continue
        candidates=np.arange(.05,1,.05)
        t=max(candidates,key=lambda t:binary_metrics(val['stage'][...,i],vs[...,i],t)['f1'])
        stage_thresholds.append(float(t))
    path=out/f'{arch}_seed{seed}.npz'
    model.save(path,{'features':feature_names,'schema':model_schema,'risk_head_trained':True,
        'stage_head_supported':supported.tolist(),'shadow_only':True,'packet_features_available':False})
    record={'architecture':arch,'seed':seed,'checkpoint':path.name,'checkpoint_sha256':sha(path),
        'state_validation_selected':selected is not None,'state_validation_mse':best,
        'state_epoch_validation_mse':state_logs,'heads_leave_state_unchanged':True,
        'stage_supported_in_development':supported.tolist(),'risk_calibration':calibration,
        'risk_thresholds':thresholds,'risk_threshold_status':threshold_status,'stage_thresholds':stage_thresholds,
        'fit_sequences':len(ids),'state_validation':state_metrics(val,predict(model,val,batch)[0])}
    write_json(out/f'{arch}_seed{seed}_frozen.json',record)
    return record


def evaluate_candidate(record, test, out):
    path=out/record['checkpoint']
    if sha(path)!=record['checkpoint_sha256']:raise ValueError('Frozen checkpoint changed')
    model,_=GraphWorldModel.load(path);mean,_,risk,stage=predict(model,test)
    risk=np.stack([calibrate(risk[:,h],record['risk_calibration'][h]) for h in range(HORIZON)],axis=1)
    horizon={};stage_metrics={};tactic_risk={}
    for h in range(HORIZON):
        name=str((h+1)*STEP);t=record['risk_thresholds'][h]
        horizon[name]={**binary_metrics(test['y'][:,h],risk[:,h],t),'brier':brier(test['y'][:,h],risk[:,h])}
        # Each tactic gets the SAME held-out benign population, never zero denominators.
        tactic_risk[name]={}
        for i,s in enumerate(STAGES):
            k=(test['stage'][:,h,i]==1)|(test['y'][:,h]==0)
            tactic_risk[name][s]=binary_metrics(test['y'][k,h],risk[k,h],t)
    for i,s in enumerate(STAGES):
        row=binary_metrics(test['stage'][...,i],stage[...,i],record['stage_thresholds'][i])
        row['supported_in_development']=bool(record['stage_supported_in_development'][i])
        stage_metrics[s]=row
    clean=(test['history_y']==0).all(1)
    trace=[]
    for index in np.flatnonzero(clean & (test['y']==1).any(1))[:3]:
        cutoff=int(test['cutoff'][index]); first=int(np.flatnonzero(test['y'][index]==1)[0])
        trace.append({'source':str(test['source'][index]),'forecast_issued_at_utc_epoch':cutoff,
            'observed_history_seconds':80,'history_labels':[int(v) for v in test['history_y'][index]],
            'horizon_seconds':[10,20,30,40],'future_risk_truth':test['y'][index].tolist(),
            'forecast_scores':risk[index].tolist(),
            'shadow_alert':bool(any(risk[index,h]>=record['risk_thresholds'][h] for h in range(HORIZON))),
            'first_future_malicious_flow_bucket_closes_at':cutoff+(first+1)*STEP,
            'compromise_time':None,'precompromise_warning_claim':False,
            'decision':'shadow review only; no automatic containment'})
    result={**record,'test_state':state_metrics(test,mean),'test_risk_per_horizon':horizon,
        'test_risk_per_native_tactic':tactic_risk,'test_stage_multilabel':stage_metrics,
        'test_clean_observed_history':{str((h+1)*STEP):binary_metrics(test['y'][clean,h],risk[clean,h],record['risk_thresholds'][h]) for h in range(HORIZON)},
        'timeline_examples':trace,
        'risk_gate_passed':all(r['gate_passed'] for r in horizon.values()),
        'five_stage_gate_passed':all(r['supported_in_development'] and r['positive_support']>=30 and r['recall']>=.8 for r in stage_metrics.values())}
    return result


def fit_logistic(train,val,output):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    def inputs(d):
        pooled=(d['x']*d['mask'][...,None]).sum(2)/np.maximum(d['mask'].sum(2,keepdims=True),1)
        return pooled.reshape(len(pooled),-1)
    scaler=StandardScaler().fit(inputs(train));x=scaler.transform(inputs(train));v=scaler.transform(inputs(val))
    models=[];arrays={'scaler_mean':scaler.mean_,'scaler_scale':scaler.scale_}
    for h in range(HORIZON):
        keep=train['y'][:,h]>=0
        if len(np.unique(train['y'][keep,h]))<2:
            models.append({'status':'INSUFFICIENT_TRAINING_LABELS'});continue
        model=LogisticRegression(C=1,max_iter=1000,random_state=42).fit(x[keep],train['y'][keep,h])
        vs=model.predict_proba(v)[:,1];t,status=threshold(val['y'][:,h],vs)
        arrays[f'coef{h}']=model.coef_[0];arrays[f'intercept{h}']=model.intercept_[0]
        models.append({'threshold':t,'threshold_status':status})
    arrays['metadata']=np.asarray(json.dumps(models));path=Path(output)/'logistic_frozen.npz'
    np.savez(path,**arrays)
    return {'checkpoint':path.name,'checkpoint_sha256':sha(path)}


def score_logistic(record,test,output):
    path=Path(output)/record['checkpoint']
    if sha(path)!=record['checkpoint_sha256']:raise ValueError('Baseline checkpoint changed')
    pooled=(test['x']*test['mask'][...,None]).sum(2)/np.maximum(test['mask'].sum(2,keepdims=True),1)
    z=np.load(path,allow_pickle=False);x=(pooled.reshape(len(pooled),-1)-z['scaler_mean'])/z['scaler_scale']
    cfg=json.loads(str(z['metadata']));report={}
    for h,row in enumerate(cfg):
        if 'threshold' not in row:report[str((h+1)*STEP)]=row;continue
        score=np.exp(-np.logaddexp(0,-(x@z[f'coef{h}']+z[f'intercept{h}'])))
        report[str((h+1)*STEP)]={**binary_metrics(test['y'][:,h],score,row['threshold']),**row,'brier':brier(test['y'][:,h],score)}
    return {'same_observed_history':True,'normalization_fit':'train_only','class_balancing':False,'per_horizon':report,**record}


def finalize(p,protocol_path,sources,train,val,ta,va,records,baseline,output):
    test,ea=load_group(sources,'test',allow_empty=True)
    if test is None:
        result={'schema':'garuda-causal-native-result-1','status':'INSUFFICIENT_FINAL_TELEMETRY',
            'protocol_sha256':sha(protocol_path),'sources':{'train':ta,'validation':va,'test':ea},
            'models_frozen':records,'test_metrics':None,'automatic_promotion':False,
            'claim_boundary':'Reserved sources do not contain usable causal sequences. No test performance or advance-warning claim is established.'}
        write_json(output/'report.json',result);return result
    if set(test['day']) & (set(train['day'])|set(val['day'])):raise ValueError('Final day leakage')
    results=[evaluate_candidate(r,test,output) for r in records]
    summary={}
    def seed_stat(values,stat):
        known=[v for v in values if v is not None]
        if not known or (stat=='seed_sd' and len(known)<2):return None
        return float(np.mean(known) if stat=='mean' else np.std(known,ddof=1))
    for arch in ('lstm','gnn_lstm'):
        rows=[r for r in results if r['architecture']==arch]
        summary[arch]={'state_improvement_mean':float(np.mean([r['test_state']['relative_improvement'] for r in rows])),
            'state_improvement_seed_sd':float(np.std([r['test_state']['relative_improvement'] for r in rows],ddof=1)),
            'state_gates_passed':sum(r['test_state']['gate_passed'] for r in rows),
            'risk_gates_passed':sum(r['risk_gate_passed'] for r in rows),
            'five_stage_gates_passed':sum(r['five_stage_gate_passed'] for r in rows),
            'risk_per_horizon':{str((h+1)*STEP):{key+'_'+stat:seed_stat([r['test_risk_per_horizon'][str((h+1)*STEP)][key] for r in rows],stat) for key in ('precision','recall','fpr','f1') for stat in ('mean','seed_sd')} for h in range(HORIZON)}}
    report={'schema':'garuda-causal-native-result-1','protocol_sha256':sha(protocol_path),
        'freeze_sha256':sha(output/'freeze.json'),'sources':{'train':ta,'validation':va,'test':ea},
        'feature_order':FEATURES,'graph_nodes':SERVICE_NODES,'summary':summary,'models':results,
        'equal_history_logistic_baseline':score_logistic(baseline,test,output),
        'automatic_promotion':False,'automatic_containment':False,
        'record_availability_certified':False,
        'timing_basis':'earliest ts+duration proxy; exporter receipts and trailing TCP packet times are unavailable',
        'claim_boundary':'Native flow-record sequence diagnostic on a held-out publisher release using an earliest session-end proxy. Actual exporter availability is unverified. Flow-only; no packet, causal live warning or successful-compromise certification. Bootstrap clusters are source days, not independent enterprises.'}
    write_json(output/'report.json',report)
    print(json.dumps({'summary':summary,'report':str(output/'report.json')}),flush=True)
    return report


def evaluate_frozen(protocol_path,cache,output,frozen_experiment,original_protocol_path):
    import shutil
    p=json.loads(Path(protocol_path).read_text());validate_protocol(p)
    original=json.loads(Path(original_protocol_path).read_text());validate_protocol(original)
    frozen_experiment=Path(frozen_experiment)
    freeze_path=frozen_experiment/'initial_freeze.json'
    if not freeze_path.exists():freeze_path=frozen_experiment/'freeze.json'
    f=json.loads(freeze_path.read_text())
    if sha(original_protocol_path)!=f['protocol_sha256']:raise ValueError('Original training protocol changed')
    if sha(freeze_path)!=p['final_source_amendment']['original_candidate_freeze_sha256']:
        raise ValueError('Candidate freeze changed')
    # Only final source selection may be amended. No architecture, fit data or threshold tuning.
    for key in original:
        if key=='sources':
            if [s for s in p[key] if s['split']!='test'] != [s for s in original[key] if s['split']!='test']:
                raise ValueError('Development sources changed after freeze')
        elif p.get(key)!=original[key]:raise ValueError('Training protocol changed after freeze: '+key)
    output=Path(output)
    if output.exists():raise ValueError('Immutable frozen evaluation output must be new')
    sources=acquire(p,Path(cache));output.mkdir(parents=True)
    write_json(output/'acquisition.json',sources)
    count=sum(s.get('split')=='train' for s in sources)
    train,ta=load_group(sources,'train',max(1,p['max_train_sequences']//count));val,va=load_group(sources,'validation',6000)
    for r in f['models']:
        old=frozen_experiment/r['checkpoint']
        if sha(old)!=r['checkpoint_sha256']:raise ValueError('Frozen candidate changed')
        shutil.copyfile(old,output/r['checkpoint'])
    baseline=fit_logistic(train,val,output)
    write_json(output/'freeze.json',{**f,'protocol_sha256':sha(protocol_path),
        'original_freeze_sha256':sha(freeze_path),'sources':sources,
        'model_refit':False,'baseline':baseline,'test_metrics_read_before_freeze':False})
    return finalize(p,protocol_path,sources,train,val,ta,va,f['models'],baseline,output)


def run(protocol_path,cache,output):
    p=json.loads(Path(protocol_path).read_text());validate_protocol(p)
    output=Path(output)
    if output.exists():raise ValueError('Immutable experiment output must be new')
    sources=acquire(p,Path(cache));output.mkdir(parents=True)
    write_json(output/'acquisition.json',sources)
    train_count=sum(s.get('split')=='train' for s in sources)
    train,ta=load_group(sources,'train',max(1,p['max_train_sequences']//train_count));val,va=load_group(sources,'validation',6000)
    if set(train['day']) & set(val['day']):raise ValueError('Observed train/validation days overlap')
    if min(int((train['y']==0).sum()),int((train['y']==1).sum()))<5:raise ValueError('Training needs both reviewed risk classes')
    records=[]
    for arch in ('lstm','gnn_lstm'):
        for seed in p['seeds']:records.append(train_candidate(arch,seed,train,val,p,output))
    # All six checkpoints, calibration and policy thresholds exist BEFORE test labels are read.
    baseline=fit_logistic(train,val,output)
    write_json(output/'freeze.json',{'protocol_sha256':sha(protocol_path),'sources':sources,
        'models':records,'baseline':baseline,'test_metrics_read_before_freeze':False,'frozen_at_epoch':time.time()})
    return finalize(p,protocol_path,sources,train,val,ta,va,records,baseline,output)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--protocol',type=Path,required=True);ap.add_argument('--cache',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--frozen-experiment',type=Path);ap.add_argument('--original-protocol',type=Path)
    args=ap.parse_args()
    if args.frozen_experiment:
        if not args.original_protocol:ap.error('--original-protocol required for frozen evaluation')
        evaluate_frozen(args.protocol,args.cache,args.output,args.frozen_experiment,args.original_protocol)
    else:run(args.protocol,args.cache,args.output)


if __name__=='__main__':main()
