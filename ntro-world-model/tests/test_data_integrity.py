import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dataset_pipeline import TrafficFeaturePipeline
from forecast_dataset import make_examples, chronological_examples

class DataIntegrityTests(unittest.TestCase):
    def load(self, timestamps, flag='0'):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'traffic.csv'
            with path.open('w') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Label', 'Dst Port', 'SYN Flag Cnt', 'Tot Fwd Pkts'])
                for ts in timestamps:
                    writer.writerow([ts, 'BENIGN', 443, flag, 2])
            return TrafficFeaturePipeline().load_cicids2018_csv(str(path))

    def test_hours_and_days_do_not_collide(self):
        times = ['01/03/2018 08:00:00', '01/03/2018 09:00:00', '02/03/2018 08:00:00', '02/03/2018 09:00:00']
        result = self.load(times)
        self.assertEqual(len(result), 4)
        self.assertEqual(result[1]['time_window'] - result[0]['time_window'], 3600)
        self.assertTrue(all(w['ground_truth'] == 0 for w in result))

    def test_bad_timestamp_is_not_synthetic_time(self):
        with self.assertRaises(ValueError):
            self.load(['invalid'] * 4)

    def test_nonfinite_counter_does_not_crash(self):
        self.assertEqual(len(self.load(['01/03/2018 08:00:00'] * 4, 'Infinity')), 1)

    def test_failed_pcap_never_becomes_simulation(self):
        class Broken:
            def __init__(self, **kwargs): pass
            def extract_windows_from_pcap(self, path): raise ValueError('invalid capture')
        with patch.dict(sys.modules, {'pcap_pipeline': SimpleNamespace(ScapyPCAPFeatureExtractor=Broken)}):
            with self.assertRaisesRegex(ValueError, 'invalid capture'):
                TrafficFeaturePipeline().parse_pcap_file('bad.pcap')

    def windows(self, n=150):
        return [dict(time_window=i*10, state_vector=[i]*12, ground_truth=int(i % 3 == 0), source_file='a') for i in range(n)]

    def test_future_target_excludes_history(self):
        examples = make_examples(self.windows(24))
        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0]['history'][-1][0], 15)
        self.assertEqual(examples[0]['future'][0][0], 16)
        self.assertGreater(examples[0]['target_start'], examples[0]['cutoff'])

    def test_gaps_and_capture_boundaries_rejected(self):
        windows = self.windows(24)
        windows[-1]['time_window'] += 10
        self.assertEqual(make_examples(windows), [])
        windows = self.windows(24)
        windows[-1]['source_file'] = 'b'
        self.assertEqual(make_examples(windows), [])

    def test_split_observations_and_targets_disjoint(self):
        splits = chronological_examples(self.windows())
        seen = []
        for split in splits:
            used = {v[0] for e in split for v in e['history'] + e['future']}
            self.assertTrue(all(used.isdisjoint(previous) for previous in seen))
            seen.append(used)

if __name__ == '__main__': unittest.main()
