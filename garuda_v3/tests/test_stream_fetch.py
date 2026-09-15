import io,json,struct,tempfile,unittest,zlib
from pathlib import Path
from unittest.mock import patch
from garuda_v3.ids2018_stream_fetch import fetch
class StreamingTests(unittest.TestCase):
 def run_member(self,bad_crc=False):
  payload=b'bounded-data-'*200000;compressor=zlib.compressobj(wbits=-15);body=compressor.compress(payload)+compressor.flush();header=struct.pack('<IHHHHHIIIHH',0x04034b50,20,0,8,0,0,zlib.crc32(payload),len(body),len(payload),0,0);archive=header+body
  class Response(io.BytesIO):
   def __init__(self,start,end):super().__init__(archive[start:end+1]);self.status=206;self.headers={'Content-Range':f'bytes {start}-{end}/{len(archive)}'}
  def urlopen(request,timeout):
   start,end=map(int,request.get_header('Range')[6:].split('-'));return Response(start,end)
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);catalog=root/'catalog.json';out=root/'capture.pcap';catalog.write_text(json.dumps({'url':'https://example.invalid/member.zip','members':[{'name':'capture','offset':0,'size':len(payload),'compressed':len(body),'crc':0 if bad_crc else zlib.crc32(payload)}]}))
   with patch('garuda_v3.ids2018_stream_fetch.urllib.request.urlopen',urlopen):
    if bad_crc:
     with self.assertRaises(ValueError):fetch(catalog,'capture',out)
     self.assertFalse(out.exists());self.assertFalse(out.with_suffix('.pcap.partial').exists())
    else:fetch(catalog,'capture',out);self.assertEqual(out.read_bytes(),payload)
 def test_large_inflation_processed_in_bounded_chunks(self):self.run_member()
 def test_bad_crc_never_commits_file(self):self.run_member(True)
