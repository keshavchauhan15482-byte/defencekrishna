import socket
import struct
import tempfile
import unittest
from pathlib import Path
from garuda_v3.pcap import convert_pcap
from garuda_v3.data import FEATURES

def fixture(path):
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for window in range(10):
            for i in range(2):
                tcp=struct.pack('!HHIIBBHHH',12000,445,100,0,0x50,0x18,4096,0,0)+b'test'
                ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0,64-i,6,0,socket.inet_aton('10.0.0.1'),socket.inet_aton('10.0.0.2'))
                packet=b'\0'*12+b'\x08\x00'+ip+tcp
                f.write(struct.pack('<IIII',window*10,i*100000,len(packet),len(packet)));f.write(packet)
class PcapTests(unittest.TestCase):
    def test_real_packet_fields_and_unknown_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'capture.pcap';fixture(p);d=convert_pcap(p)
            self.assertEqual(len(d['times']),9);self.assertTrue((d['y']==-1).all())
            self.assertEqual(d['metadata']['node_names'][0],['10.0.0.1','10.0.0.2'])
            self.assertAlmostEqual(float(d['x'][0,0,FEATURES.index('ttl_mean_scaled')]),63.5/255,places=5)
            self.assertEqual(float(d['x'][0,0,FEATURES.index('packet_features_present')]),1)
            self.assertEqual(float(d['x'][0,0,FEATURES.index('duplicate_payload_segment_fraction')]),.5)
    def test_truncated_capture_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'bad.pcap';p.write_bytes(b'bad')
            with self.assertRaises(ValueError):convert_pcap(p)

if __name__=='__main__':unittest.main()
