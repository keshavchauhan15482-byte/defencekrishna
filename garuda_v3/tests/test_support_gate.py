import json,unittest
from pathlib import Path
import numpy as np
from garuda_v3.support_gate import fit,score
from garuda_v3.inference import ForecastService

class SupportTests(unittest.TestCase):
    def test_validation_fitted_gate_rejects_shift_without_labels(self):
        x=np.full((10,3,4,21),.2,dtype='float32');m=np.ones((10,3,4),dtype='float32')
        gate=fit(x,m,x,m)
        self.assertTrue((score(gate,x,m)<=gate['threshold']).all())
        self.assertTrue((score(gate,x+.5,m)>gate['threshold']).all())
    def test_real_host_packet_checkpoint_and_abstention(self):
        folder=Path(__file__).resolve().parents[1]/'artifacts/ids2018_host_run'
        service=ForecastService(folder)
        self.assertEqual(service.meta['mode'],'host');self.assertTrue(service.meta['packet_features_trained'])
        self.assertIsNotNone(service.support_gate)
        payload=json.loads((folder/'replay.json').read_text())
        payload['x']=(np.ones_like(payload['x'])*np.asarray(payload['mask'])[:,:,None]).tolist()
        with self.assertRaisesRegex(ValueError,'training support'):service.predict(payload)

class CaptureAuditTests(unittest.TestCase):
    def test_invalid_record_and_partial_tail_mark_whole_windows_unknown(self):
        import tempfile,struct,hashlib
        from garuda_v3.tests.test_pcap import fixture
        from garuda_v3.ids2018_prepare import clean
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'original.pcap';fixture(p)
            raw=bytearray(p.read_bytes());raw[56:58]=b'\0\0'
            raw.extend(struct.pack('<IIII',95,0,80,80)+b'partial')
            p.write_bytes(raw);before=hashlib.sha256(raw).hexdigest()
            derivative,audit=clean(p,root,step=10)
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),before)
            self.assertEqual(audit['removed_records']['invalid_ip_length'],1)
            self.assertEqual(audit['removed_records']['incomplete_record_payload'],1)
            self.assertEqual(audit['excluded_windows'],[0,90])
            self.assertLess(derivative.stat().st_size,p.stat().st_size)

if __name__=='__main__':unittest.main()
