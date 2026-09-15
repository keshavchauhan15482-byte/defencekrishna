"""Bounded, provenance-preserving public telemetry adapters. No inferred labels.

python -m garuda_v3.multisource pcapng INPUT --output OUTPUT --campaign ID
python -m garuda_v3.multisource ctu INPUT --output OUTPUT --campaign ID
"""
import argparse
import csv
import hashlib
import json
import struct
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from .data import FEATURES, SCHEMA, graph_snapshot, save_dataset, timestamp
from .pcap import convert_pcap


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(1024 * 1024):
            h.update(b)
    return h.hexdigest()


def ng_records(path):
    """Strict PCAPNG SHB/IDB/EPB reader; timestamps include IDB resolution/offset.

    Other timestamped packet representations are rejected, never silently lost.
    Supports Ethernet interfaces only for this version of the network adapter.
    """
    interfaces = []; endian = None; previous = None
    with open(path, 'rb') as f:
        while header := f.read(8):
            if len(header) != 8:
                raise ValueError('Truncated PCAPNG block header')
            section = header[:4] == b'\x0a\x0d\x0d\x0a'
            prefix = f.read(4) if section else b''
            if section:
                endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(prefix)
                interfaces = []
            if endian is None:
                raise ValueError('Invalid/missing PCAPNG section')
            kind, size = struct.unpack(endian + 'II', header)
            if size < 12 + len(prefix) or size % 4 or size > 16 * 1024 * 1024:
                raise ValueError('Invalid PCAPNG block size')
            body = prefix + f.read(size - 8 - len(prefix))
            if len(body) != size - 8 or struct.unpack(endian+'I', body[-4:])[0] != size:
                raise ValueError('Truncated/mismatched PCAPNG block')
            body = body[:-4]
            if section:
                if len(body) < 16 or struct.unpack(endian+'HH',body[4:8]) != (1,0):
                    raise ValueError('Unsupported PCAPNG version')
            elif kind == 1:
                if len(body) < 8:
                    raise ValueError('Short interface block')
                link, _, snap = struct.unpack(endian+'HHI', body[:8])
                if link != 1:
                    raise ValueError('Only Ethernet PCAPNG is supported')
                unit = 1e6; offset = 0; pos = 8
                while pos + 4 <= len(body):
                    code, n = struct.unpack(endian+'HH', body[pos:pos+4]); pos += 4
                    value = body[pos:pos+n]
                    if len(value) != n:
                        raise ValueError('Truncated interface option')
                    pos += (n+3)//4*4
                    if code == 0: break
                    if code == 9:
                        if n != 1: raise ValueError('Invalid timestamp resolution')
                        unit = (2 if value[0]&128 else 10) ** (value[0]&127)
                    if code == 14:
                        if n != 8: raise ValueError('Invalid timestamp offset')
                        offset = struct.unpack(endian+'q',value)[0]
                interfaces.append((snap, unit, offset))
            elif kind == 6:
                if len(body) < 20: raise ValueError('Short enhanced packet block')
                interface, high, low, n, original = struct.unpack(endian+'IIIII',body[:20])
                if interface >= len(interfaces): raise ValueError('Unknown packet interface')
                snap, unit, offset = interfaces[interface]
                if n > original or n > 262144 or (snap and n > snap) or len(body) < 20+(n+3)//4*4:
                    raise ValueError('Invalid enhanced packet length')
                t = ((high << 32) | low) / unit + offset
                if previous is not None and t < previous:
                    raise ValueError('Out-of-order packets: sort capture explicitly before conversion')
                previous = t
                yield t, original, body[20:20+n]
            elif kind in (2, 3):
                raise ValueError('Unsupported legacy/simple packet block')


def pcapng_graph(path, campaign, mode='host', window=60, max_nodes=64):
    """Process ten-minute chunks; memory is bounded independently of file size."""
    pieces = []; records = 0; current = None; out = None; excluded = set()
    first = last = None; removed = Counter()
    with tempfile.TemporaryDirectory(prefix='garuda-ng-') as tmp:
        part = Path(tmp)/'window.pcap'
        def finish(final):
            nonlocal out
            if out is None: return
            out.close(); out = None
            d = convert_pcap(part, mode, window, max_packets=2000000,
                             max_nodes=max_nodes, drop_last=False)
            keep = ~np.isin(d['times'], list(excluded))
            if final: keep &= d['times'] < int(last//window)*window
            # First partially observed bucket is not a complete state.
            keep &= d['times'] > int(first//window)*window
            for k in ('x','adj','mask','y','times'): d[k] = d[k][keep]
            d['metadata']['node_names'] = [n for n,k in zip(d['metadata']['node_names'],keep) if k]
            if len(d['times']): pieces.append(d)
        for t, original, raw in ng_records(path):
            first = t if first is None else first; last = t
            bucket = int(t//(window*10))
            if bucket != current:
                finish(False); current = bucket
                out = part.open('wb')
                out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,1))
            records += 1
            # Truncated Ethernet/IP records invalidate the entire observed window.
            if len(raw) < original:
                excluded.add(int(t//window)*window); removed['snaplen_truncation'] += 1; continue
            sec = int(t); sub = int(round((t-sec)*1e6))
            if sub == 1000000: sec += 1; sub = 0
            out.write(struct.pack('<IIII',sec,sub,len(raw),original)); out.write(raw)
        finish(True)
    if not pieces: raise ValueError('No complete valid graph windows')
    data = {k:np.concatenate([d[k] for d in pieces]) for k in ('x','adj','mask','y','times')}
    meta = dict(pieces[0]['metadata'])
    meta.update(source_sha256=sha256(path), source_filename=Path(path).name,
        campaign_id=campaign, dataset_id='CICAPT-IIoT2024', windows=len(data['times']),
        node_names=[n for d in pieces for n in d['metadata']['node_names']],
        raw_records=records, excluded_windows=sorted(excluded), removed_records=dict(removed),
        timestamp_semantics='PCAPNG IDB resolution/offset; completed packet windows',
        label_provenance='No verified attack timeline supplied; all risk/stage labels unknown',
        preprocessing='Ten-minute bounded chunks; first and final partial windows excluded',
        commercial_rights_verified=False, automatic_containment_approved=False)
    data['metadata'] = meta
    return data


def ctu_graph(path, campaign, window=60):
    """CTU detailed bidirectional flows; service graph, explicit missing features.

    Raw file is start-time ordered, so end-time buckets are spooled to disk before
    sorting. Retain at most one bucket of decoded flow objects in memory.
    """
    # Bound memory by spooling canonical rows by end-time bucket to temporary files.
    labels = Counter(); count = 0
    with tempfile.TemporaryDirectory(prefix='garuda-ctu-') as tmp:
        handles = {}; paths = {}
        with open(path, newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            required = {'StartTime','Dur','Proto','SrcAddr','DstAddr','Dport','TotPkts','TotBytes','Label'}
            if not required <= set(reader.fieldnames or []): raise ValueError('CTU schema mismatch')
            for row in reader:
                count += 1
                if count > 10000000: raise ValueError('CTU row budget exceeded')
                start = timestamp(row['StartTime']); duration = float(row['Dur'])
                if not np.isfinite(duration) or duration < 0: raise ValueError('Invalid duration')
                end = start+duration; bucket = int(end//window)*window
                label = row['Label'].casefold()
                y = None if 'background' in label else 1 if 'botnet' in label else 0 if 'normal' in label else None
                labels[str(y)] += 1
                proto = row['Proto'].lower(); port = row['Dport'].strip()
                # ICMP types/codes are not TCP/UDP service ports.
                p = int(port,16) if port.lower().startswith('0x') else int(port or 0)
                if not 0 <= p <= 65535: raise ValueError('Invalid destination port')
                packets = float(row['TotPkts']); byte_count = float(row['TotBytes'])
                if not all(np.isfinite(v) and v >= 0 for v in (packets,byte_count)): raise ValueError('Invalid flow counters')
                flow = dict(start=start,end=end,duration=duration,packets=packets,bytes=byte_count,
                    bwd=0,protocol=proto if proto in ('tcp','udp') else 'other',port=p if proto in ('tcp','udp') else 0,
                    flags=[0,0,0,0],src=row['SrcAddr'],dst=row['DstAddr'],label=y,
                    iat_ms=None,tcp_window=0,window_present=False,packet_present=False)
                if bucket not in paths:
                    if len(paths) >= 10000: raise ValueError('CTU window budget exceeded')
                    paths[bucket] = Path(tmp)/str(bucket)
                # Bounded descriptor cache; append avoids retaining millions of rows.
                if bucket not in handles:
                    if len(handles) >= 128:
                        _, old = handles.popitem(); old.close()
                    handles[bucket] = paths[bucket].open('a')
                handles[bucket].write(json.dumps(flow,separators=(',',':'))+'\n')
        for f in handles.values(): f.close()
        xs=[];ads=[];masks=[];ys=[];times=[];names=[]
        for bucket,p in sorted(paths.items()):
            with p.open() as f: flows = [json.loads(line) for line in f]
            x,a,m,nn = graph_snapshot(flows,'service',32)
            observed = {flow['label'] for flow in flows}
            xs.append(x); ads.append(a); masks.append(m); times.append(bucket); names.append(nn)
            ys.append(1 if 1 in observed else -1 if None in observed else 0)
    meta = dict(schema=SCHEMA,features=FEATURES,mode='service',max_nodes=32,
        window_seconds=window,source_sha256=sha256(path),source_filename=Path(path).name,
        campaign_id=campaign,dataset_id='CTU-13',windows=len(times),node_names=names,
        packet_features=False,synthetic=False,row_labels=dict(labels),raw_records=count,
        timestamp_semantics='Completed flow end; naive publisher clock treated as UTC, no cross-source synchronization',
        missing_features=['TCP flag counts','backward packet counts','IAT','TTL','TCP window','fragments','retransmissions'],
        missing_feature_policy='Unavailable fields encoded zero; availability documented; use within-source evaluation',
        topology='protocol-to-service incidence; not enterprise host topology',
        label_provenance='Publisher detailed labels: Botnet=1, Normal=0, Background/other=unknown',
        automatic_containment_approved=False)
    return dict(x=np.array(xs),adj=np.array(ads),mask=np.array(masks),y=np.array(ys,dtype=np.int8),times=np.array(times),metadata=meta)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind',choices=['pcapng','ctu']);p.add_argument('input')
    p.add_argument('--output',required=True);p.add_argument('--campaign',required=True)
    p.add_argument('--mode',choices=['host','service'],default='host')
    p.add_argument('--max-nodes',type=int,default=64);p.add_argument('--window',type=int,default=60)
    a=p.parse_args()
    if a.window < 1 or a.max_nodes < 32: p.error('Invalid window/node capacity')
    d = pcapng_graph(a.input,a.campaign,a.mode,a.window,a.max_nodes) if a.kind=='pcapng' else ctu_graph(a.input,a.campaign,a.window)
    save_dataset(d,a.output)
    print(json.dumps({k:v for k,v in d['metadata'].items() if k!='node_names'},indent=2))


if __name__=='__main__': main()
