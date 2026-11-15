import tempfile
import unittest
import zipfile
from pathlib import Path
from garuda_v3.ait_source_audit import audit, inspect_zip


class SourceAuditTests(unittest.TestCase):
    def archive(self, directory, content):
        p=Path(directory)/'fixture.zip'
        with zipfile.ZipFile(p,'w') as z:
            z.writestr('sensor/flows.csv',content)
            z.writestr('do-not-run.py','raise RuntimeError("not data")')
        return p

    def test_real_labels_preserved_not_guessed_as_mitre(self):
        with tempfile.TemporaryDirectory() as d:
            r=inspect_zip(self.archive(d,'timestamp,label\n1,benign_share\n2,upload_rce_shell\n3,\n'))
            self.assertEqual(r['rows'],3)
            self.assertEqual(r['label_counts']['<unknown>'],1)
            self.assertFalse(r['five_stage_training_approved'])
            self.assertFalse((Path(d)/'do-not-run.py').exists())

    def test_delimiter_and_case(self):
        with tempfile.TemporaryDirectory() as d:
            r=inspect_zip(self.archive(d,'timestamp;Label\n1;service_scan\n'))
            self.assertEqual(r['label_counts'],{'service_scan':1})

    def test_ambiguous_missing_and_duplicate_labels_rejected(self):
        for header in ['timestamp,label,attack\n1,a,b\n','timestamp,value\n1,a\n','timestamp,label,label\n1,a,b\n']:
            with self.subTest(header=header),tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError): inspect_zip(self.archive(d,header))

    def test_reserved_campaign_never_acquired(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'Reserved'): audit('wilson',d,Path(d)/'result.json')
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_bad_cached_checksum_never_decoded(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'fox_netflows.zip').write_bytes(b'not publisher bytes')
            with self.assertRaisesRegex(ValueError,'checksum'): audit('fox',d,Path(d)/'out.json')
            self.assertFalse((Path(d)/'out.json').exists())


if __name__=='__main__': unittest.main()
