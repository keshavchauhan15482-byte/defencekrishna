import unittest
from datetime import datetime, timezone
from garuda_v3.upload_inference import analyze
class UploadTests(unittest.TestCase):
 def test_csv_runs_checkpoint_without_labels(self):
  raw=('Timestamp,Flow Duration,Protocol,Dst Port\n'+''.join(f'{datetime.fromtimestamp(1700000000+i*10,timezone.utc).isoformat()},1,6,80\n' for i in range(24))).encode()
  d=analyze(raw,'csv','garuda_v3/artifacts/residual_run')
  self.assertTrue(d['forecasts'])
  self.assertFalse(d['automatic_containment'])
  self.assertFalse(d['v48_benchmark_model'])
  self.assertTrue(d['forecasts'][0]['explanation']['feature_attributions'])
 def test_invalid(self):
  for raw,kind in [(b'','csv'),(b'abc','zip'),(b'bad','pcap')]:
   with self.assertRaises(ValueError):analyze(raw,kind,'garuda_v3/artifacts/residual_run')
