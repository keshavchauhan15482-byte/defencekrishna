import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from garuda_v3.ps_complete import FEATURES, SCHEMA, graph_snapshot, load_dataset, save_dataset, summarize
from garuda_v3.train_v46 import _validate_contract, _validate_manifest


class V46PSCompleteTests(unittest.TestCase):
    def flow(self, **overrides):
        base = dict(
            src="10.0.0.1", dst="10.0.0.2", port=80, protocol="tcp",
            duration=.2, packets=4, bytes=400, bwd=1,
            flags=[1, 3, 0, 0, 2, 1],
            iat_ms=10., iat_variance=25., iat_max=15., tcp_window=4096.,
            ttl_mean=64., ttl_var=4., fragment_fraction=.25,
            payload_mean=50., payload_variance=100., payload_max=100., payload_present=True,
            retransmission_count=1, packet_present=True, window_present=True,
            scan_events=[(1., "10.0.0.2", 80), (2., "10.0.0.2", 81), (3., "10.0.0.2", 443)],
            label=None,
        )
        base.update(overrides)
        return base

    def test_official_ps_features_are_explicit(self):
        required = {
            "psh_fraction", "urg_fraction", "iat_variance_log", "iat_max_log",
            "payload_mean_log", "payload_variance_log", "payload_max_log",
            "unique_destination_ports_log", "sequential_port_transition_fraction",
            "random_port_transition_fraction", "retransmission_count_log",
        }
        self.assertTrue(required.issubset(FEATURES))
        self.assertEqual(len(FEATURES), len(set(FEATURES)))

    def test_summary_is_bounded_and_uses_scan_sequence(self):
        vector = summarize([self.flow()])
        self.assertEqual(vector.shape, (len(FEATURES),))
        self.assertTrue(np.isfinite(vector).all())
        self.assertTrue(((0 <= vector) & (vector <= 1)).all())
        self.assertGreater(vector[FEATURES.index("psh_fraction")], 0)
        self.assertGreater(vector[FEATURES.index("urg_fraction")], 0)
        self.assertGreater(vector[FEATURES.index("sequential_port_transition_fraction")], 0)
        self.assertGreater(vector[FEATURES.index("random_port_transition_fraction")], 0)
        self.assertEqual(vector[FEATURES.index("scan_sequence_present")], 1)

    def test_graph_keeps_real_host_topology(self):
        x, adj, mask, names = graph_snapshot([self.flow()], mode="host", max_nodes=4)
        self.assertEqual(set(names), {"10.0.0.1", "10.0.0.2"})
        self.assertEqual(int(mask.sum()), 2)
        a, b = names.index("10.0.0.1"), names.index("10.0.0.2")
        self.assertEqual(adj[b, a], 1)
        self.assertEqual(x.shape, (4, len(FEATURES)))

    def test_loader_rejects_schema_drift(self):
        data = dict(
            x=np.zeros((2, 4, len(FEATURES)), dtype=np.float32),
            adj=np.zeros((2, 4, 4), dtype=np.float32),
            mask=np.ones((2, 4), dtype=np.float32),
            y=np.array([-1, -1], dtype=np.int8),
            times=np.array([0, 10], dtype=np.int64),
            metadata=dict(schema=SCHEMA, features=FEATURES, mode="host", window_seconds=10,
                          max_nodes=4, source_sha256="a" * 64, campaign_id="a"),
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "a.npz"
            save_dataset(data, path)
            loaded = load_dataset(path)
            self.assertEqual(loaded["metadata"]["schema"], SCHEMA)

            broken = dict(data)
            broken["metadata"] = dict(data["metadata"], features=FEATURES[:-1])
            bad = Path(td) / "bad.npz"
            save_dataset(broken, bad)
            with self.assertRaises(ValueError):
                load_dataset(bad)

    def test_contract_and_manifest_are_fail_closed(self):
        def dataset(campaign, source):
            return dict(
                x=np.zeros((20, 4, len(FEATURES)), dtype=np.float32),
                adj=np.zeros((20, 4, 4), dtype=np.float32),
                mask=np.ones((20, 4), dtype=np.float32),
                y=np.full(20, -1, dtype=np.int8), times=np.arange(20) * 10,
                metadata=dict(schema=SCHEMA, features=FEATURES, mode="host", window_seconds=10,
                              max_nodes=4, source_sha256=source, campaign_id=campaign),
            )
        datasets = [dataset("train-a", "a" * 64), dataset("val-a", "b" * 64), dataset("test-a", "c" * 64)]
        _validate_contract(datasets)
        _validate_manifest(datasets, {"train": ["train-a"], "validation": ["val-a"], "test": ["test-a"]})
        with self.assertRaises(ValueError):
            _validate_manifest(datasets, {"train": ["train-a"], "validation": ["val-a"], "test": ["val-a"]})


if __name__ == "__main__":
    unittest.main()
