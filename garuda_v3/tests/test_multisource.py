import csv
import struct
import tempfile
import unittest
from pathlib import Path
import numpy as np
from garuda_v3.multisource import ng_records, ctu_graph, pcapng_graph
from garuda_v3.pcap import convert_pcap
from garuda_v3.tests.test_pcap import fixture


def block(kind,body):
    body += b'\0' * (-len(body)%4)
    n=len(body)+12
    return struct.pack('<II',kind,n)+body+struct.pack('<I',n)


def capture(timestamps,resolution=6):
    shb=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    idb=block(1,struct.pack('<HHI',1,0,65535)+struct.pack('<HH',9,1)+bytes([resolution])+b'\0'*3)
    return shb+idb+b''.join(block(6,struct.pack('<IIIII',0,t>>32,t&0xffffffff,4,4)+b'abcd') for t in timestamps)


class MultisourceTests(unittest.TestCase):
    def test_chunk_boundaries_preserve_complete_windows(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'classic';fixture(p)
            raw=p.read_bytes();offset=24;records=[]
            # Spread fixture windows across the ten-window chunk boundary.
            while offset < len(raw):
                sec,sub,n,original=struct.unpack('<IIII',raw[offset:offset+16]);offset+=16
                ts=(sec+95)*1000000+sub
                records.append(block(6,struct.pack('<IIIII',0,ts>>32,ts&0xffffffff,n,original)+raw[offset:offset+n]))
                offset+=n
            ng=Path(t)/'capture.pcapng'
            ng.write_bytes(capture([])+b''.join(records))
            result=pcapng_graph(ng,'test',window=10,max_nodes=32)
            self.assertTrue(np.all(np.diff(result['times'])==10))
            self.assertEqual(len(np.unique(result['times'])),len(result['times']))
            self.assertEqual(result['metadata']['raw_records'],len(records))
            self.assertTrue(np.all(result['y']==-1))

    def test_pcapng_resolution_and_exact_payload(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'capture';p.write_bytes(capture([1234567890],9))
            records=list(ng_records(p))
            self.assertAlmostEqual(records[0][0],1.234567890)
            self.assertEqual(records[0][2],b'abcd')

    def test_malformed_or_out_of_order_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'capture'
            for raw in (capture([2,1]),capture([1])[:-1]):
                p.write_bytes(raw)
                with self.assertRaises(ValueError):list(ng_records(p))

    def test_ctu_unknown_and_end_time(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'flows.csv'
            fields=['StartTime','Dur','Proto','SrcAddr','DstAddr','Dport','TotPkts','TotBytes','Label']
            with p.open('w') as f:
                w=csv.writer(f);w.writerow(fields)
                w.writerow(['2011/08/15 16:43:00.000000',120,'tcp','a','b','80',1,40,'Background'])
                w.writerow(['2011/08/15 16:44:00.000000',0,'tcp','a','b','80',1,40,'Botnet'])
                w.writerow(['2011/08/15 16:46:00.000000',0,'udp','a','b','53',1,40,'Normal'])
            d=ctu_graph(p,'test')
            np.testing.assert_array_equal(d['y'],[1,-1,0])
            self.assertFalse(d['metadata']['packet_features'])
            self.assertTrue(np.all(d['x'][:,:,18]==0))


if __name__=='__main__':unittest.main()
