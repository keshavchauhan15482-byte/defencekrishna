import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from garuda_v3.data import FEATURES, SCHEMA, load_dataset
from garuda_v3.prepare_v45_data import prepare


def fake_packet_dataset():
    return {
        "x": np.zeros((3, 64, len(FEATURES)), dtype=np.float32),
        "adj": np.zeros((3, 64, 64), dtype=np.float32),
        "mask": np.ones((3, 64), dtype=np.float32),
        "y": np.full(3, -1, dtype=np.int8),
        "times": np.asarray([0, 10, 20], dtype=np.int64),
        "metadata": {
            "schema": SCHEMA,
            "features": FEATURES,
            "mode": "host",
            "window_seconds": 10,
            "max_nodes": 64,
            "source_sha256": "a" * 64,
            "source_filename": "capture.pcap",
            "packet_features": True,
        },
    }


class PrepareV45DataTests(unittest.TestCase):
    def test_ids_packet_path_preserves_unknown_truth_and_packet_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "packet.npz")
            args = argparse.Namespace(
                kind="ids2018-pcap",
                input="capture.pcap",
                output=output,
                campaign="ids-packet-a",
                family="DoS",
                mode="host",
                max_nodes=64,
                max_packets=5000,
            )
            with patch("garuda_v3.prepare_v45_data.convert_pcap", return_value=fake_packet_dataset()) as convert:
                prepared = prepare(args)
            convert.assert_called_once_with(
                "capture.pcap",
                mode="host",
                window_seconds=10,
                max_packets=5000,
                max_nodes=64,
                drop_last=True,
            )
            self.assertTrue((prepared["y"] == -1).all())
            self.assertEqual(prepared["metadata"]["campaign_id"], "ids-packet-a")
            self.assertEqual(prepared["metadata"]["dataset_id"], "CIC-IDS-2018")
            self.assertTrue(prepared["metadata"]["packet_features"])
            self.assertFalse(prepared["metadata"]["risk_labels_attached"])
            self.assertFalse(prepared["metadata"]["verified_timeline_used_as_feature"])
            loaded = load_dataset(output)
            self.assertEqual(loaded["metadata"]["window_seconds"], 10)
            self.assertTrue((loaded["y"] == -1).all())

    def test_ctu_remains_separate_evaluation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "ctu.npz")
            args = argparse.Namespace(
                kind="ctu",
                input="capture.binetflow",
                output=output,
                campaign="ctu-5",
                family=None,
                mode="service",
                max_nodes=64,
                max_packets=5000,
            )
            data = fake_packet_dataset()
            data["metadata"].update(mode="service", max_nodes=32, dataset_id="CTU-13")
            with patch("garuda_v3.prepare_v45_data.ctu_graph", return_value=data):
                prepared = prepare(args)
            self.assertEqual(prepared["metadata"]["v45_role"], "separate_evaluation_only")


if __name__ == "__main__":
    unittest.main()
