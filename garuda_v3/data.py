"""Observed flow graphs. Service graphs do not assert host topology.
All completed flow features enter at END time, never retroactively at start time.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np

SCHEMA = 'garuda-observed-graph-v3.1'
FEATURES = ['flow_count_log', 'bytes_log', 'packets_log', 'duration_ms_log',
            'syn_fraction', 'ack_fraction', 'rst_fraction', 'fin_fraction',
            'backward_packet_fraction', 'tcp_fraction', 'udp_fraction', 'active',
            'iat_ms_log', 'tcp_window_log', 'ttl_mean_scaled', 'ttl_variance_scaled',
            'fragment_fraction', 'duplicate_payload_segment_fraction', 'packet_features_present',
            'iat_present', 'tcp_window_present']
PORTS = [20, 21, 22, 25, 53, 80, 110, 123, 135, 139, 143, 443, 445, 3389, 8080]
SERVICE_NODES = ['protocol:tcp', 'protocol:udp', 'protocol:other'] + [f'service:{p}' for p in PORTS] + ['service:other']
MAX_NODES = 32

def timestamp(value):
    value = str(value).strip()
    for fmt in ('%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S.%f', '%Y/%m/%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp()
    except ValueError:
        raise ValueError('Missing/invalid full capture timestamp') from None


def number(row, names, default=0.):
    for name in names:
        if name in row and str(row[name]).strip():
            try:
                n = float(row[name])
                if not math.isfinite(n) or n < 0:
                    raise ValueError(f'Invalid numeric field {name}')
                return n
            except (TypeError, ValueError):
                raise ValueError(f'Invalid numeric field {name}') from None
    return default


def pick(row, names, default=''):
    return next((str(row[k]).strip() for k in names if row.get(k) is not None), default)


def attack_label(text):
    text = text.strip().casefold()
    if not text or text == 'background' or 'background' in text:
        return None  # CTU background is not automatically benign
    if text in ('benign', 'normal', '0') or 'normal' in text:
        return 0
    return 1


def read_flows(path):
    """CIC CSV or canonical endpoint CSV. Unknown labels stay unknown."""
    with Path(path).open(newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        columns = {c.strip() for c in (reader.fieldnames or [])}
        for choices in ({'Timestamp','timestamp','StartTime'}, {'Flow Duration','duration_us','Dur'}, {'Protocol','protocol','Proto'}, {'Dst Port','Destination Port','dst_port','Dport'}):
            if not columns.intersection(choices):
                raise ValueError('Required completed-flow column missing: ' + '/'.join(sorted(choices)))
        for index, raw in enumerate(reader, 2):
            if index > 250002:
                raise ValueError('Flow limit exceeded; partition capture explicitly')
            row = {k.strip(): v for k, v in raw.items() if k is not None}
            time_text = pick(row, ['Timestamp', 'timestamp', 'StartTime'])
            if time_text.casefold() in ('timestamp', 'starttime'):
                continue
            try:
                start = timestamp(time_text)
                duration = number(row, ['Flow Duration', 'duration_us']) / 1e6
                if 'Dur' in row:
                    duration = number(row, ['Dur'])
                fwd = number(row, ['Tot Fwd Pkts', 'Total Fwd Packets', 'fwd_packets'])
                bwd = number(row, ['Tot Bwd Pkts', 'Total Backward Packets', 'bwd_packets'])
                packets = number(row, ['TotPkts'], fwd + bwd)
                byte_count = number(row, ['TotBytes'], number(row, ['TotLen Fwd Pkts', 'Total Length of Fwd Packets', 'fwd_bytes']) + number(row, ['TotLen Bwd Pkts', 'Total Length of Bwd Packets', 'bwd_bytes']))
                protocol = pick(row, ['Protocol', 'protocol', 'Proto']).lower()
                protocol = 'tcp' if protocol in ('6', 'tcp') else ('udp' if protocol in ('17', 'udp') else 'other')
                port_text = pick(row, ['Dst Port', 'Destination Port', 'dst_port', 'Dport'], '0')
                port = int(float(port_text or 0))
                if not 0 <= port <= 65535:
                    raise ValueError('Invalid port')
                flags = [number(row, names) for names in (
                    ['SYN Flag Cnt', 'SYN Flag Count', 'syn'], ['ACK Flag Cnt', 'ACK Flag Count', 'ack'],
                    ['RST Flag Cnt', 'RST Flag Count', 'rst'], ['FIN Flag Cnt', 'FIN Flag Count', 'fin'])]
                yield dict(start=start, end=start + duration, duration=duration, packets=packets,
                           bwd=bwd, bytes=byte_count, protocol=protocol, port=port, flags=flags,
                           src=pick(row, ['Src IP', 'Source IP', 'src_ip', 'SrcAddr']),
                           dst=pick(row, ['Dst IP', 'Destination IP', 'dst_ip', 'DstAddr']),
                           label=attack_label(pick(row, ['Label', 'label'])),
                           iat_ms=number(row, ['Flow IAT Mean'])/1000 if 'Flow IAT Mean' in row else None,
                           tcp_window=max(0.,float(pick(row,['Init Fwd Win Byts'],'0') or 0)),
                           window_present='Init Fwd Win Byts' in row, packet_present=False)
            except (ValueError, TypeError) as exc:
                raise ValueError(f'Row {index}: {exc}') from exc


def logscale(value, scale):
    return min(1., math.log1p(value) / math.log1p(scale))


def summarize(flows):
    if not flows:
        return np.zeros(len(FEATURES), dtype=np.float32)
    n = len(flows)
    packets = sum(f['packets'] for f in flows)
    flags = [sum(min(1., f['flags'][i]) for f in flows) / n for i in range(4)]
    return np.array([logscale(n, 10000), logscale(sum(f['bytes'] for f in flows), 1e9),
        logscale(packets, 1e7), logscale(sum(f['duration'] for f in flows) * 1000 / n, 1e7),
        *flags, sum(f['bwd'] for f in flows) / max(packets, 1),
        sum(f['protocol'] == 'tcp' for f in flows) / n,
        sum(f['protocol'] == 'udp' for f in flows) / n, 1.,
        logscale(sum(f.get('iat_ms') or 0. for f in flows)/max(1,sum(f.get('iat_ms') is not None for f in flows)),1e6),
        logscale(sum(f.get('tcp_window',0.) for f in flows)/n,65535),
        sum(f.get('ttl_mean',0.) for f in flows)/n/255,
        min(1.,sum(f.get('ttl_var',0.) for f in flows)/n/1000),
        sum(f.get('fragment_fraction',0.) for f in flows)/n,
        sum(f.get('retransmission_fraction',0.) for f in flows)/n,
        sum(bool(f.get('packet_present')) for f in flows)/n,
        sum(f.get('iat_ms') is not None for f in flows)/n,
        sum(bool(f.get('window_present')) for f in flows)/n], dtype=np.float32)


def graph_snapshot(flows, mode='service', max_nodes=MAX_NODES):
    if mode not in ('service', 'host'):
        raise ValueError('Graph mode must be service or host')
    if mode == 'service':
        names = SERVICE_NODES
    else:
        if any(not f['src'] or not f['dst'] for f in flows):
            raise ValueError('Host graph requires real source/destination identifiers; choose service mode for this CSV')
        names = sorted({f[k] for f in flows for k in ('src', 'dst')})
    if len(names) > max_nodes:
        raise ValueError(f'Graph exceeds {max_nodes} nodes; partition by sensor/subnet, never silently drop hosts')
    mapping = {name: i for i, name in enumerate(names)}
    node_flows = defaultdict(list)
    adj = np.zeros((max_nodes, max_nodes), dtype=np.float32)
    for f in flows:
        if mode == 'service':
            a = mapping[f"protocol:{f['protocol']}"]
            b = mapping[f"service:{f['port']}"] if f['port'] in PORTS else mapping['service:other']
        else:
            a, b = mapping[f['src']], mapping[f['dst']]
        node_flows[a].append(f)
        if a != b:
            node_flows[b].append(f)
        adj[b, a] += 1  # directed incoming messages, receiver x sender
    features = np.zeros((max_nodes, len(FEATURES)), dtype=np.float32)
    mask = np.zeros(max_nodes, dtype=np.float32)
    for node, observed in node_flows.items():
        features[node] = summarize(observed)
        mask[node] = 1
    return features, adj, mask, names


def convert(path, mode='service', window_seconds=10, max_nodes=MAX_NODES):
    if window_seconds <= 0 or max_nodes < len(SERVICE_NODES):
        raise ValueError('Invalid graph dimensions/window size')
    groups = defaultdict(list)
    labels = Counter()
    for f in read_flows(path):
        groups[int(f['end'] // window_seconds) * window_seconds].append(f)
        if len(groups) > 10000:
            raise ValueError('Window limit exceeded; partition capture explicitly')
        labels[str(f['label'])] += 1
    if not groups:
        raise ValueError('No observed flows')
    xs, adjs, masks, ys, times, names = [], [], [], [], [], []
    for t, flows in sorted(groups.items()):
        x, a, m, node_names = graph_snapshot(flows, mode, max_nodes)
        xs.append(x); adjs.append(a); masks.append(m); times.append(t); names.append(node_names)
        observed = [f['label'] for f in flows]
        # Unknown mixed traffic cannot establish negative ground truth.
        ys.append(1 if 1 in observed else (-1 if None in observed else 0))
    metadata = dict(schema=SCHEMA, features=FEATURES, mode=mode, window_seconds=window_seconds,
                    max_nodes=max_nodes, source_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                    source_filename=Path(path).name, row_labels=dict(labels), windows=len(times),
                    timestamp_semantics='completed_flow_end_time; naive timestamps assumed UTC',
                    packet_features=False, topology='protocol-to-service incidence' if mode == 'service' else 'observed endpoint flows',
                    node_names=names, synthetic=False)
    return dict(x=np.array(xs), adj=np.array(adjs), mask=np.array(masks), y=np.array(ys,dtype=np.int8),
                times=np.array(times,dtype=np.int64), metadata=metadata)


def save_dataset(data, output):
    output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output, **{k:v for k,v in data.items() if k != 'metadata'}, metadata=json.dumps(data['metadata']))


def load_dataset(path):
    with np.load(path, allow_pickle=False) as z:
        d = {k:z[k] for k in ('x','adj','mask','y','times')}
        if 'stage_y' in z: d['stage_y']=z['stage_y']
        d['metadata'] = json.loads(str(z['metadata']))
    if d['metadata']['schema'] != SCHEMA:
        raise ValueError('Feature schema mismatch')
    return d


def build_examples(datasets, history=12, horizon=6, stride=2):
    """Global chronological raw-window split, then isolated examples per capture."""
    if min(history, horizon, stride) < 1:
        raise ValueError('Invalid sequence dimensions')
    hashes = [d['metadata']['source_sha256'] for d in datasets]
    if len(set(hashes)) != len(hashes):
        raise ValueError('Duplicate capture hash')
    schemas = {(d['metadata']['mode'], d['metadata']['window_seconds'], d['metadata']['max_nodes']) for d in datasets}
    if len(schemas) != 1:
        raise ValueError('Do not mix graph schemas')
    all_times = np.unique(np.concatenate([d['times'] for d in datasets]))
    if len(all_times) < 3 * (history + horizon):
        raise ValueError('Too few observed windows')
    cut1, cut2 = all_times[int(len(all_times)*.6)], all_times[int(len(all_times)*.8)]
    splits = [[], [], []]
    for source, d in enumerate(datasets):
        t = d['times']; step = d['metadata']['window_seconds']
        for split, keep in enumerate((t < cut1, (t >= cut1) & (t < cut2), t >= cut2)):
            indices = np.flatnonzero(keep)
            for j in range(0, len(indices)-history-horizon+1, stride):
                ids = indices[j:j+history+horizon]
                if np.any(np.diff(t[ids]) != step) or np.any(d['y'][ids] < 0):
                    continue
                splits[split].append((source, int(ids[0])))
    if any(not split for split in splits):
        raise ValueError('Empty split: need more contiguous labelled captures')
    return splits, dict(train_before=int(cut1), validation_before=int(cut2))

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv'); parser.add_argument('--output',required=True)
    parser.add_argument('--mode', choices=['service','host'], default='service')
    args=parser.parse_args(); d=convert(args.csv,args.mode); save_dataset(d,args.output)
    print(json.dumps({k:v for k,v in d['metadata'].items() if k!='node_names'},indent=2))


def campaign_examples(datasets, manifest, history=8, horizon=4, stride=8, allow_unknown=False):
    """Predeclared campaign-held-out split. Every capture and campaign assigned once."""
    hashes=[d['metadata']['source_sha256'] for d in datasets]
    if len(set(hashes))!=len(hashes):raise ValueError('Duplicate capture hash')
    schemas={(d['metadata']['mode'],d['metadata']['window_seconds'],d['metadata']['max_nodes']) for d in datasets}
    if len(schemas)!=1:raise ValueError('Do not mix graph schemas')
    if min(history,horizon,stride)<1:raise ValueError('Invalid sequence dimensions')
    assignments={};groups=set()
    for split,name in enumerate(('train','validation','test')):
        campaigns=manifest.get(name,[])
        if not campaigns:raise ValueError('Every split needs explicit campaign IDs')
        for campaign in campaigns:
            if not isinstance(campaign,str) or not campaign or campaign in groups:raise ValueError('Campaign overlap or invalid campaign ID')
            groups.add(campaign);assignments[campaign]=split
    actual={d['metadata'].get('campaign_id') for d in datasets}
    if actual!=groups:raise ValueError('Manifest must assign every and only supplied campaign')
    splits=[[],[],[]]
    for source,d in enumerate(datasets):
        split=assignments[d['metadata']['campaign_id']];step=d['metadata']['window_seconds']
        for start in range(0,len(d['times'])-history-horizon+1,stride):
            stop=start+history+horizon
            if np.any(np.diff(d['times'][start:stop])!=step) or (not allow_unknown and np.any(d['y'][start:stop]<0)):continue
            splits[split].append((source,start))
    if any(not s for s in splits):raise ValueError('Empty campaign split')
    return splits,dict(method='predeclared campaign holdout',manifest=manifest)


def development_examples(datasets, manifest, history=8, horizon=4, stride=8, allow_unknown=False):
    """Blocked development split with embargo; entire test campaigns remain untouched."""
    development=manifest.get('development',[]);test=manifest.get('test',[])
    if not development or not test or len(set(development+test))!=len(development+test):raise ValueError('Distinct development/test campaigns required')
    fraction=manifest.get('development_fraction',.7);embargo=manifest.get('embargo_windows',history+horizon)
    if not .2<=fraction<=.8 or not isinstance(embargo,int) or embargo<history+horizon:raise ValueError('Invalid development fraction or embargo')
    hashes=[d['metadata']['source_sha256'] for d in datasets]
    if len(set(hashes))!=len(hashes):raise ValueError('Duplicate capture hash')
    if {d['metadata'].get('campaign_id') for d in datasets}!=set(development+test):raise ValueError('Manifest/capture mismatch')
    if len({(d['metadata']['mode'],d['metadata']['window_seconds'],d['metadata']['max_nodes']) for d in datasets})!=1:raise ValueError('Mixed graph schemas')
    splits=[[],[],[]];boundaries=[]
    for s,d in enumerate(datasets):
        n=len(d['times']);cut=int(n*fraction);is_test=d['metadata']['campaign_id'] in test
        boundaries.append(dict(campaign=d['metadata']['campaign_id'],cut=cut,embargo_windows=embargo,test_only=is_test))
        for start in range(0,n-history-horizon+1,stride):
            stop=start+history+horizon
            if np.any(np.diff(d['times'][start:stop])!=d['metadata']['window_seconds']) or (not allow_unknown and np.any(d['y'][start:stop]<0)):continue
            group=2 if is_test else 0 if stop<=cut else 1 if start>=cut+embargo else None
            if group is not None:splits[group].append((s,start))
    if any(not split for split in splits):raise ValueError('Empty development/test split')
    return splits,dict(method='blocked development validation with embargo and entire held-out test campaigns',boundaries=boundaries,manifest=manifest)
