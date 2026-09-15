"""Packet-derived observed graphs from bounded classic PCAP decoding."""
from collections import defaultdict
from pathlib import Path
import hashlib
import numpy as np
from .data import graph_snapshot, SCHEMA, FEATURES, MAX_NODES

def convert_pcap(path,mode='host',window_seconds=10,max_packets=250000,max_nodes=MAX_NODES,drop_last=True):
    from .pcap_reader import packets as read_packets
    groups=defaultdict(lambda:defaultdict(list))
    for packet in read_packets(path,max_packets):
        ends=sorted([(packet['src'],packet['sport']),(packet['dst'],packet['dport'])])
        key=(ends[0],ends[1],packet['protocol'])
        w=int(packet['t']//window_seconds)*window_seconds
        groups[w][key].append(packet)
    if not groups:raise ValueError('No IP packets in capture')
    xs=[];adjs=[];masks=[];times=[];names=[]
    for w,connections in sorted(groups.items()):
        flows=[]
        for (left,right,protocol),packets in connections.items():
            packets.sort(key=lambda p:p['t']);first=packets[0];seen=set();retrans=0
            for p in packets:
                seg=(p['src'],p['sport'],p['seq'],p['payload_len'])
                if p['payload_len']>0:
                    retrans+=seg in seen;seen.add(seg)
            ttls=np.array([p['ttl'] for p in packets]); iats=np.diff([p['t'] for p in packets])*1000
            # Direction follows first observed packet, not claimed client/server role.
            forward=(first['src'],first['sport'])
            flows.append(dict(src=first['src'],dst=first['dst'],port=first['dport'],protocol=protocol,
                start=packets[0]['t'],end=packets[-1]['t'],duration=packets[-1]['t']-packets[0]['t'],
                packets=len(packets),bytes=sum(p['bytes'] for p in packets),
                bwd=sum((p['src'],p['sport'])!=forward for p in packets),
                flags=[sum(bool(p['flags']&bit) for p in packets) for bit in (2,16,4,1)],
                iat_ms=float(iats.mean()) if len(iats) else None,tcp_window=float(np.mean([p['win'] for p in packets])),
                ttl_mean=float(ttls.mean()),ttl_var=float(ttls.var()),fragment_fraction=sum(p['frag'] for p in packets)/len(packets),
                retransmission_fraction=retrans/len(packets),packet_present=True,window_present=protocol=='tcp',label=None))
        x,a,m,nn=graph_snapshot(flows,mode,max_nodes);xs.append(x);adjs.append(a);masks.append(m);times.append(w);names.append(nn)
    meta=dict(schema=SCHEMA,features=FEATURES,mode=mode,window_seconds=window_seconds,max_nodes=max_nodes,
        source_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),source_filename=Path(path).name,
        packet_features=True,synthetic=False,node_names=names,windows=len(times),
        timestamp_semantics='closed packet windows; unknown ground truth',
        limitations=['duplicate TCP payload segments are a retransmission indicator, not full TCP reassembly','classic PCAP Ethernet/raw IPv4 supported; other families need an adapter','capture-end partial window excluded'])
    # Last bucket may not have closed at capture end. Do not pretend it was available.
    if drop_last and len(times)<2:raise ValueError('Need at least two packet windows; last may be incomplete')
    stop=-1 if drop_last else None
    meta['node_names']=names[:stop];meta['windows']=len(times[:stop])
    return dict(x=np.array(xs[:stop]),adj=np.array(adjs[:stop]),mask=np.array(masks[:stop]),
                y=np.full(len(times[:stop]),-1,dtype=np.int8),times=np.array(times[:stop]),metadata=meta)
