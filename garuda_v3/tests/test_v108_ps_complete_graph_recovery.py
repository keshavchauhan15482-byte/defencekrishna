from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import numpy as np

from garuda_v3.data import SCHEMA as V31_SCHEMA
from garuda_v3.model import GraphWorldModel
from garuda_v3.ps_complete import FEATURES, SCHEMA, summarize
from garuda_v3.v108_ps_complete_graph_recovery import REQUIRED_PS_FEATURES


class V108Contracts(unittest.TestCase):
    def test_ps_complete_schema_contains_required_features(self):
        self.assertEqual(SCHEMA, 'garuda-observed-graph-v46-ps-complete')
        self.assertEqual(len(FEATURES), 34)
        self.assertTrue(REQUIRED_PS_FEATURES.issubset(set(FEATURES)))
        self.assertIn('payload_mean_log', FEATURES)
        self.assertIn('sequential_port_transition_fraction', FEATURES)
        self.assertIn('retransmission_count_log', FEATURES)

    def test_ps_complete_summary_has_no_legacy_semantic_alias(self):
        flow = {
            'packets': 2, 'bytes': 100, 'duration': .1, 'flags': [1,1,0,0,1,0],
            'bwd': 1, 'protocol': 'tcp', 'iat_ms': 10., 'iat_variance': 4., 'iat_max': 12.,
            'tcp_window': 2048., 'ttl_mean': 64., 'ttl_var': 2., 'fragment_fraction': 0.,
            'payload_mean': 20., 'payload_variance': 5., 'payload_max': 25.,
            'payload_present': True, 'retransmission_count': 1, 'packet_present': True,
            'window_present': True, 'scan_events': [(1.0,'10.0.0.2',80),(2.0,'10.0.0.2',81)],
        }
        x = summarize([flow])
        self.assertEqual(x.shape, (34,))
        self.assertGreater(x[FEATURES.index('payload_mean_log')], 0)
        self.assertGreater(x[FEATURES.index('sequential_port_transition_fraction')], 0)
        self.assertGreater(x[FEATURES.index('retransmission_fraction')], 0)

    def test_model_roundtrip_supports_old_and_ps_complete_schemas(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old = GraphWorldModel(feature_dim=21, schema=V31_SCHEMA)
            old_path = root/'old.npz'
            old.save(old_path, {'kind':'old'})
            old2, _ = GraphWorldModel.load(old_path)
            self.assertEqual(old2.schema, V31_SCHEMA)
            new = GraphWorldModel(feature_dim=len(FEATURES), schema=SCHEMA)
            new_path = root/'new.npz'
            new.save(new_path, {'kind':'new'})
            new2, _ = GraphWorldModel.load(new_path)
            self.assertEqual(new2.schema, SCHEMA)
            self.assertEqual(new2.f, len(FEATURES))

    def test_forward_rejects_wrong_feature_dimension(self):
        model = GraphWorldModel(feature_dim=len(FEATURES), schema=SCHEMA)
        x = np.zeros((1, 8, 32, 21), dtype=np.float32)
        a = np.zeros((1, 8, 32, 32), dtype=np.float32)
        m = np.ones((1, 8, 32), dtype=np.float32)
        with self.assertRaises(ValueError):
            model.forward(x, a, m, 4)


if __name__ == '__main__':
    unittest.main()
