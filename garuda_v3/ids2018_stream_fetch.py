"""Bounded streaming extraction of larger official ZIP members; verifies size, CRC and SHA."""
import hashlib,json,struct,urllib.request,zlib
from pathlib import Path

def fetch(catalog,member,output):
 d=json.loads(Path(catalog).read_text());info=next(m for m in d['members'] if m['name']==member)
 if not 0<info['size']<=512*1024**2 or not 0<info['compressed']<=512*1024**2:raise ValueError('Member exceeds 512-MiB streaming budget')
 out=Path(output);partial=out.with_suffix(out.suffix+'.partial')
 if out.exists() or partial.exists():raise ValueError('Output exists; preserve original data')
 def request(start,size):
  r=urllib.request.urlopen(urllib.request.Request(d['url'],headers={'Range':f'bytes={start}-{start+size-1}'}),timeout=60)
  if r.status!=206 or not r.headers.get('Content-Range','').startswith(f'bytes {start}-{start+size-1}/'):r.close();raise ValueError('Exact byte range unavailable')
  return r
 with request(info['offset'],30) as r:header=r.read(31)
 if len(header)!=30:raise ValueError('Invalid ZIP header length')
 fields=struct.unpack('<IHHHHHIIIHH',header)
 if fields[0]!=0x04034b50 or fields[2]&1 or fields[3] not in (0,8):raise ValueError('Unsupported ZIP member')
 offset=info['offset']+30+fields[-2]+fields[-1];decoder=zlib.decompressobj(-15) if fields[3]==8 else None
 count=0;crc=0;sha=hashlib.sha256();out.parent.mkdir(parents=True,exist_ok=True)
 try:
  with partial.open('xb') as dst,request(offset,info['compressed']) as src:
   remaining=info['compressed']
   while remaining:
    chunk=src.read(min(1024**2,remaining))
    if not chunk:raise ValueError('Truncated compressed stream')
    remaining-=len(chunk);pending=chunk
    while pending:
     data=decoder.decompress(pending,1024**2) if decoder else pending
     pending=decoder.unconsumed_tail if decoder else b''
     count+=len(data)
     if count>info['size']:raise ValueError('Decompressed size limit exceeded')
     dst.write(data);crc=zlib.crc32(data,crc);sha.update(data)
   if src.read(1):raise ValueError('Unexpected compressed data')
  if count!=info['size'] or crc!=info['crc'] or (decoder and (not decoder.eof or decoder.unused_data)):raise ValueError('ZIP integrity verification failed')
  partial.rename(out)
 except BaseException:
  partial.unlink(missing_ok=True);raise
 out.with_suffix(out.suffix+'.source.json').write_text(json.dumps({**info,'source_url':d['url'],'sha256':sha.hexdigest(),'original_member_crc_verified':True,'extraction':'bounded streaming; 1 MiB decompression chunks'},indent=2))
 print(json.dumps({'output':str(out),'size':count,'crc_verified':True}),flush=True)
if __name__=='__main__':
 import sys
 fetch(*sys.argv[1:])
