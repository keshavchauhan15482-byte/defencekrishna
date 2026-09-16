import unittest

try:
    import numpy as np
    import pandas as pd
    from garuda_v3 import v48_toniot_unseen as v48
    V48_DEPS = True
except ModuleNotFoundError:
    np = None
    pd = None
    v48 = None
    V48_DEPS = False


@unittest.skipUnless(V48_DEPS, 'V48 research deps are intentionally separate from production runtime')
class V48ToNIoTTests(unittest.TestCase):
    def test_schema_is_network_only(self):
        n = 20
        df = pd.DataFrame({
            'ts': np.arange(n) + 1700000000,
            'src_ip': ['10.0.0.1'] * n,
            'src_port': np.arange(n) + 1000,
            'dst_port': np.arange(n) + 2000,
            'duration': np.arange(n) + 1,
            'src_bytes': np.arange(n) + 2,
            'dst_bytes': np.arange(n) + 3,
            'missed_bytes': np.arange(n),
            'src_pkts': np.arange(n) + 4,
            'src_ip_bytes': np.arange(n) + 5,
            'dst_pkts': np.arange(n) + 6,
            'dst_ip_bytes': np.arange(n) + 7,
            'label': [0, 1] * 10,
            'type': ['normal', 'scanning'] * 10,
            'process_memory': np.arange(n) + 100,
            'ossec_alert': np.arange(n) + 200,
        })
        schema = v48.resolve_schema(df)
        self.assertGreaterEqual(len(schema['features']), 8)
        self.assertNotIn('process_memory', schema['features'].values())
        self.assertNotIn('ossec_alert', schema['features'].values())
        self.assertNotIn('label', schema['features'].values())
        self.assertNotIn('type', schema['features'].values())

    def test_family_split_removes_heldout_family_from_development(self):
        seq = {
            'history_families': np.asarray([frozenset(), frozenset({'novel'}), frozenset(), frozenset()], dtype=object),
            'step_families': np.asarray([
                (frozenset(),) * 4,
                (frozenset(),) * 4,
                (frozenset({'novel'}), frozenset(), frozenset(), frozenset()),
                (frozenset(),) * 4,
            ], dtype=object),
            'clean': np.asarray([True, False, True, True]),
            'y': np.asarray([0, 0, 1, 0], dtype=np.int8),
        }
        masks = {
            'train': np.asarray([True, True, True, False]),
            'calibration': np.asarray([False] * 4),
            'policy': np.asarray([False] * 4),
            'test': np.asarray([False, False, True, True]),
        }
        split = v48.family_split(seq, masks, 'novel')
        self.assertTrue(split['train'][0])
        self.assertFalse(split['train'][1])
        self.assertFalse(split['train'][2])
        self.assertTrue(split['test_positive'][2])
        self.assertTrue(split['clean_positive'][2])
        self.assertTrue(split['test_negative'][3])

    def test_frozen_hybrid_weights_and_policy_reserve(self):
        self.assertAlmostEqual(v48.FUSION_RISK_WEIGHT + v48.FUSION_WORLD_WEIGHT, 1.0)
        self.assertEqual(v48.FUSION_RISK_WEIGHT, 0.75)
        self.assertEqual(v48.POLICY_FPR_RESERVE, 0.005)
        self.assertEqual(v48.RELEASE_FPR, 0.01)
        self.assertEqual(v48.RELEASE_RECALL, 0.80)

    def test_benign_percentile_is_monotone(self):
        ref = np.asarray([1.0, 2.0, 3.0, 4.0])
        score = v48.benign_percentile(np.asarray([0.5, 2.5, 5.0]), ref)
        self.assertTrue(np.all(np.diff(score) >= 0))
        self.assertEqual(score[-1], 1.0)


if __name__ == '__main__':
    unittest.main()
