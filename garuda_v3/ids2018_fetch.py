"""Extract one bounded member from an official S3 ZIP using HTTP ranges; verify CRC and SHA.
Usage: python -m garuda_v3.ids2018_fetch CATALOG MEMBER OUTPUT
"""
import urllib.request,struct,zlib,json,hashlib,sys
from pathlib import Path

def fetch(catalog,member,out):
 d=json.loads(Path(catalog).read_text());info=next(x for x in d['members'] if x['name']==member)
 if info['size']>512*1024**2 or info['compressed']>128*1024**2:raise ValueError('Selected member exceeds bounded extraction budget')
 def get(start,n):
  req=urllib.request.Request(d['url'],headers={'Range':f'bytes={start}-{start+n-1}'})
  with urllib.request.urlopen(req,timeout=60) as r:
   if r.status!=206 or not r.headers.get('Content-Range','').startswith(f'bytes {start}-{start+n-1}/'):raise ValueError('Exact range unavailable')
   data=r.read(n+1)
  if len(data)!=n:raise ValueError('Incomplete range')
  return data
 header=get(info['offset'],30);fields=struct.unpack('<IHHHHHIIIHH',header)
 if fields[0]!=0x04034b50 or fields[2]&1:raise ValueError('Invalid/encrypted member')
 method=fields[3];offset=info['offset']+30+fields[-2]+fields[-1]
 raw=get(offset,info['compressed'])
 if method==8:
  decoder=zlib.decompressobj(-15);data=decoder.decompress(raw,info['size']+1)
  if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:raise ValueError('Invalid deflate payload')
 elif method==0:data=raw
 else:raise ValueError('Unsupported compression')
 if len(data)!=info['size'] or zlib.crc32(data)!=info['crc']:raise ValueError('ZIP integrity failed')
 out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
 meta={**info,'source_url':d['url'],'sha256':hashlib.sha256(data).hexdigest(),'original_member_crc_verified':True}
 out.with_suffix(out.suffix+'.source.json').write_text(json.dumps(meta,indent=2));print(str(out),meta['size'],data[:24].hex(),flush=True)
if __name__=='__main__':fetch(*sys.argv[1:])
