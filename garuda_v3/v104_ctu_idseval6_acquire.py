"""V104 acquisition-only identity freeze for CTU-IDSEVAL-6 pcap.zip.

This code may inspect only archive bytes and ZIP central-directory metadata. It never
extracts a PCAP member, decodes packets, reads labels, constructs graphs, or invokes
the model. The first metadata-only attempt revealed 12 PCAP members for the six
publisher-described logical capture scenarios; V104 now freezes all 12 members.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def file_hash(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prereg', required=True, type=Path)
    p.add_argument('--archive', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()

    prereg = json.loads(args.prereg.read_text())
    if prereg['status'] != 'ACQUISITION_ONLY_HASH_PENDING' or prereg['evaluation_permitted'] is not False:
        raise RuntimeError('V104 acquisition requires fail-closed HASH_PENDING preregistration')
    ext = prereg['external_holdout']
    if args.archive.name != ext['archive_filename']:
        raise RuntimeError('Archive filename mismatch')
    observed_md5 = file_hash(args.archive, 'md5')
    if observed_md5 != ext['official_archive_md5']:
        raise RuntimeError(f'Official pcap.zip MD5 mismatch: {observed_md5}')
    observed_sha256 = file_hash(args.archive, 'sha256')

    with zipfile.ZipFile(args.archive, 'r') as zf:
        bad = zf.testzip()
        if bad is not None:
            raise RuntimeError(f'ZIP CRC integrity failure: {bad}')
        entries = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            entries.append({
                'filename': info.filename,
                'compressed_bytes': int(info.compress_size),
                'uncompressed_bytes': int(info.file_size),
                'crc32_hex': f'{info.CRC:08x}',
            })
    entries.sort(key=lambda r: r['filename'])
    pcap_entries = [r for r in entries if r['filename'].lower().endswith(('.pcap', '.pcapng'))]
    non_pcap = [r['filename'] for r in entries if r not in pcap_entries]
    expected_members = int(ext['archive_pcap_member_count'])
    if len(pcap_entries) != expected_members:
        raise RuntimeError(f'Expected exactly {expected_members} frozen PCAP members, found {len(pcap_entries)}')
    if non_pcap:
        raise RuntimeError(f'Unexpected non-PCAP members in registered pcap.zip: {non_pcap}')

    report = {
        'schema_version': 'v104-acquisition.1',
        'status': 'HASH_AND_ENTRY_METADATA_FROZEN_MODEL_NOT_RUN',
        'evaluation_performed': False,
        'archive_extracted': False,
        'packet_records_decoded': False,
        'graph_windows_constructed': False,
        'support_scoring_performed': False,
        'model_inference_performed': False,
        'labels_accessed': False,
        'archive_filename': args.archive.name,
        'archive_bytes': int(args.archive.stat().st_size),
        'archive_md5': observed_md5,
        'archive_sha256': observed_sha256,
        'publisher_logical_capture_count': int(ext['publisher_logical_capture_count']),
        'pcap_entry_count': len(pcap_entries),
        'pcap_entries': pcap_entries,
        'aggregate_uncompressed_pcap_bytes': int(sum(r['uncompressed_bytes'] for r in pcap_entries)),
        'member_policy': 'all 12 PCAP members are frozen for the one-shot; no selection/drop permitted',
        'next_step': 'Pin archive SHA-256 and the full sorted 12-member manifest into preregistration before any extraction or packet decode.'
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
