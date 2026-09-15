import unittest,tempfile,json
from pathlib import Path
from garuda_v3.shadow_agent import ShadowAgent
class ShadowTests(unittest.TestCase):
 def test_bad_capture_withheld_and_deduplicated(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'bad.pcap.ready';p.write_bytes(b'not a pcap')
   a=ShadowAgent(Path(__file__).resolve().parents[1]/'artifacts/residual_run',root/'audit.sqlite')
   try:
    r=a.process(p);self.assertEqual(r['status'],'withheld');self.assertFalse(r['automatic_containment']);self.assertEqual(a.process(p)['status'],'already_processed')
    link=root/'link.pcap.ready';link.symlink_to(p)
    with self.assertRaises(ValueError):a.process(link)
    self.assertEqual(a.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
   finally:a.db.close()
 def test_local_packet_inference_stays_shadow(self):
  import struct
  from garuda_v3.tests.test_pcap import fixture
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'capture.pcap.ready';fixture(p)
   b=bytearray(p.read_bytes());offset=24
   while offset<len(b):
    sec,sub,n,original=struct.unpack('<IIII',b[offset:offset+16]);b[offset:offset+4]=struct.pack('<I',sec*6);offset+=16+n
   p.write_bytes(b)
   a=ShadowAgent(Path(__file__).resolve().parents[1]/'artifacts/calibrated_host_v6',root/'audit.sqlite')
   try:
    r=a.process(p);self.assertEqual(r['status'],'forecast');self.assertEqual(len(r['trajectory']),4);self.assertTrue(0<=r['score']<=100);self.assertFalse(r['automatic_containment'])
   finally:a.db.close()
