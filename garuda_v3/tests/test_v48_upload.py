import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
import pandas as pd


@unittest.skipUnless(importlib.util.find_spec('torch'), 'Optional V48 research dependencies required')
class UploadTests(unittest.TestCase):
    def test_labels_not_inputs_and_missing_seed_fails(self):
        from garuda_v3.v48_upload import analyze_v48
        names = ['Bytes__mean','Bytes__std','Bytes__max','flow_count']
        class FakeRuntime:
            def __init__(self, path):
                self.meta = json.loads((path/'manifest.json').read_text())
            def predict(self, X, feature_names):
                self.assertions = (X.shape[1:] == (8, 4), feature_names == names)
                if not all(self.assertions): raise AssertionError('Feature contract mismatch')
                return {'score': np.ones(len(X)), 'alert': np.zeros(len(X),bool),
                        'components': {'transition_energy': np.ones(len(X))},
                        'transfer_feature_contributions': np.zeros((len(X),4)), 'transition_feature_energy': np.zeros((len(X),4)),
                        'state_scaled': np.zeros((len(X),4,4))}
        df = pd.DataFrame({'Date': ['2026-01-01']*10,
            'Timestamp': [f'00:{i:02d}:00' for i in range(10)],
            'Scr_IP': ['10.0.0.1']*10, 'Bytes': np.arange(10), 'class1': ['benign']*10})
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'GARUDA_V48_RUNTIME_DIR': tmp}), patch('garuda_v3.v48_upload.V48Runtime', FakeRuntime):
            for seed in (42,43,44):
                p=Path(tmp)/str(seed);p.mkdir()
                (p/'manifest.json').write_text(json.dumps({'seed':seed,'arrays_sha256':str(seed),'feature_names':names,'threshold':2}))
            a=analyze_v48(df.to_csv(index=False).encode())
            df['class1']='exploitation'
            b=analyze_v48(df.to_csv(index=False).encode())
            self.assertEqual(a['forecasts'], b['forecasts'])
            self.assertEqual(len(a['forecasts']),3)
            self.assertFalse(a['automatic_containment'])
            (Path(tmp)/'44'/'manifest.json').unlink()
            with self.assertRaisesRegex(ValueError,'missing seeds'):
                analyze_v48(df.to_csv(index=False).encode())

    def test_missing_installation_fails_explicitly(self):
        from garuda_v3.v48_upload import analyze_v48
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError,'not installed'):
                analyze_v48(b'x\n1\n')
