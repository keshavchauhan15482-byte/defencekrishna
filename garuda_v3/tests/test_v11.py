import tempfile
import unittest
from pathlib import Path
from garuda_v3.v11_readiness import freeze_holdout

class V11EvidenceTests(unittest.TestCase):
    def test_reused_source_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'Previously used'):
                freeze_holdout({'previously_used_source_hashes':['a'*64]},['a'*64],Path(t)/'frozen.json')
    def test_manifest_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'frozen.json';r={'previously_used_source_hashes':[]}
            freeze_holdout(r,['b'*64],p)
            with self.assertRaises(FileExistsError):freeze_holdout(r,['c'*64],p)

if __name__=='__main__':unittest.main()
