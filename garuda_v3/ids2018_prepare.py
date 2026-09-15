import struct,json,hashlib,socket,sys,uuid
from pathlib import Path
from collections import Counter
import numpy as np
from garuda_v3.pcap_reader import packets
from garuda_v3.pcap import convert_pcap
from garuda_v3.data import save_dataset

def clean(path,output_root,step=60):
 out=output_root/'clean'/path.name;out.parent.mkdir(exist_ok=True)
 temporary=out.with_name(out.name+'.'+uuid.uuid4().hex+'.tmp')
 bad=set();count=0;removed=Counter();first=None;last=None
 with path.open('rb') as src,temporary.open('xb') as dst:
  header=src.read(24)
  if header[:4]!=b'\xd4\xc3\xb2\xa1' or struct.unpack('<I',header[20:])[0]!=1:raise ValueError('Expected little-endian Ethernet PCAP')
  dst.write(header)
  while rec:=src.read(16):
   if len(rec)!=16:
    removed['incomplete_record_header']+=1
    if last is not None:bad.add(last//step*step)
    break
   sec,sub,n,original=struct.unpack('<IIII',rec)
   if n>262144 or n>original:raise ValueError('Invalid bounded record')
   raw=src.read(n);first=sec if first is None else first;last=sec
   if len(raw)!=n:bad.add(sec//step*step);removed['incomplete_record_payload']+=1;break
   if len(raw)>=34 and raw[12:14]==b'\x08\x00':
    ip=raw[14:];ihl=(ip[0]&15)*4;length=struct.unpack('!H',ip[2:4])[0]
    if ihl<20 or length<ihl or length>len(ip):bad.add(sec//step*step);removed['invalid_ip_length']+=1;continue
   dst.write(rec);dst.write(raw);count+=1
 temporary.replace(out)
 meta=dict(original_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),derivative_sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
  retained_records=count,removed_records=dict(removed),excluded_windows=sorted(bad),first_epoch=first,last_epoch=last,
  method='Preserve complete original records; exclude every graph window touching an invalid/truncated record. No imputation.')
 (output_root/'clean'/(path.stem+'.audit.json')).write_text(json.dumps(meta,indent=2))
 return out,meta

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description='Audited extraction of valid PCAP windows; no imputation')
 parser.add_argument('--data-root',default='datasets/ids2018')
 ROOT=Path(parser.parse_args().data_root)
 for path in sorted((ROOT/'raw').glob('*.pcap')):
  cleaned,audit=clean(path,ROOT)
  try:
   data=convert_pcap(cleaned,window_seconds=60,max_packets=1000000,max_nodes=64)
   keep=~np.isin(data['times'],audit['excluded_windows'])
   for key in ('x','adj','mask','y','times'):data[key]=data[key][keep]
   data['metadata']['node_names']=[n for n,k in zip(data['metadata']['node_names'],keep) if k]
   data['metadata'].update(windows=len(data['times']),campaign_id=path.stem,original_sha256=audit['original_sha256'],preprocessing_audit=audit)
   dest=ROOT/'graphs'/(path.stem+'.npz');save_dataset(data,dest)
   print(path.stem,'graphs',len(data['times']),'max_nodes',int(data['mask'].sum(1).max()),'removed',audit['removed_records'],'excluded',len(audit['excluded_windows']),flush=True)
  except Exception as e:print(path.stem,'BLOCKED',str(e),flush=True)
