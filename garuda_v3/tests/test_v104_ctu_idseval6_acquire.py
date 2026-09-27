from __future__ import annotations

import unittest
import zipfile

from garuda_v3.v104_ctu_idseval6_acquire import (
    classify_entries,
    is_ignorable_packaging_metadata,
)


def info(name: str, size: int = 1) -> zipfile.ZipInfo:
    item = zipfile.ZipInfo(name)
    item.file_size = size
    item.compress_size = size
    item.CRC = 0
    return item


class V104AcquisitionMetadataTests(unittest.TestCase):
    def test_known_macos_sidecar_is_packaging_metadata(self):
        self.assertTrue(is_ignorable_packaging_metadata('__MACOSX/._pcap'))
        self.assertTrue(is_ignorable_packaging_metadata('__MACOSX/scenario/._capture.pcap'))
        self.assertTrue(is_ignorable_packaging_metadata('__MACOSX/.DS_Store'))

    def test_non_macos_dot_underscore_is_not_silently_ignored(self):
        self.assertFalse(is_ignorable_packaging_metadata('._pcap'))
        self.assertFalse(is_ignorable_packaging_metadata('notes.txt'))
        self.assertFalse(is_ignorable_packaging_metadata('__MACOSX/readme.txt'))

    def test_all_pcap_members_are_preserved_and_sidecar_is_recorded(self):
        infos = [info(f'pcap/scenario-{i:02d}.pcap') for i in range(12)]
        infos.append(info('__MACOSX/._pcap'))
        pcaps, ignored, unexpected = classify_entries(infos)
        self.assertEqual(len(pcaps), 12)
        self.assertEqual([x['filename'] for x in ignored], ['__MACOSX/._pcap'])
        self.assertEqual(unexpected, [])

    def test_meaningful_non_pcap_payload_fails_classification_contract(self):
        infos = [info('pcap/capture.pcap'), info('README.txt')]
        pcaps, ignored, unexpected = classify_entries(infos)
        self.assertEqual(len(pcaps), 1)
        self.assertEqual(ignored, [])
        self.assertEqual(unexpected, ['README.txt'])


if __name__ == '__main__':
    unittest.main()
