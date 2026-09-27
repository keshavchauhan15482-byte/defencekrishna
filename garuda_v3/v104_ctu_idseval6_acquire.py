"""V104 acquisition-only identity freeze for CTU-IDSEVAL-6 pcap.zip.

This code may inspect only archive bytes and ZIP central-directory metadata. It never
extracts a PCAP member, decodes packets, reads labels, constructs graphs, or invokes
the model. The first metadata-only attempt revealed 12 PCAP members for the six
publisher-described logical capture scenarios; V104 freezes all 12 members.

Known packaging-only AppleDouble entries under ``__MACOSX/`` are ignored as ZIP
metadata, but are recorded in the acquisition manifest. Any other non-PCAP payload
fails closed. This policy is based only on central-directory metadata observed before
external packet extraction/decoding and never selects or drops a PCAP member.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath


def file_hash(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def is_ignorable_packaging_metadata(filename: str) -> bool:
    """Return True only for known macOS packaging metadata paths.

    Classification uses the ZIP member name only. It never opens/extracts the member.
    AppleDouble resource-fork sidecars have a ``._`` basename and are commonly stored
    below ``__MACOSX/``. ``.DS_Store`` is likewise packaging metadata. No ordinary
    payload file is ignored by this helper.
    """
    path = PurePosixPath(filename)
    parts = path.parts
    if not parts or parts[0] != '__MACOSX__':
        return False
    basename = path.name
    return basename.startswith('._') or basename == '.DS_Store'


def classify_entries(infos: list[zipfile.ZipInfo]) -> tuple[list[dict], list[dict], list[str]]:
    """Classify central-directory entries without extracting archive member bytes."""
    pcap_entries: list[dict] = []
    ignored_metadata: list[dict] = []
    unexpected_payloads: list[str] = []
    for info in infos:
        if info.is_dir():
            continue
        row = {
            'filename': info.filename,
            'compressed_bytes': int(info.compress_size),
            'uncompressed_bytes': int(info.file_size),
            'crc32_hex': f'{info.CRC:08x}',
        }
        lower = info.filename.lower()
        if lower.endswith(('.pcap', '.pcapng')):
            pcap_entries.append(row)
        elif is_ignorable_packaging_metadata(info.filename):
            ignored_metadata.append(row)
        else:
            unexpected_payloads.append(info.filename)
    pcap_entries.sort(key=lambda r: r['filename'])
    ignored_metadata.sort(key=lambda r: r['filename'])
    unexpected_payloads.sort()
    return pcap_entries, ignored_metadata, unexpected_payloads


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
        pcap_entries, ignored_metadata, unexpected_payloads = classify_entries(zf.infolist())

    expected_members = int(ext['archive_pcap_member_count'])
    if len(pcap_entries) != expected_members:
        raise RuntimeError(f'Expected exactly {expected_members} frozen PCAP members, found {len(pcap_entries)}')
    if unexpected_payloads:
        raise RuntimeError(f'Unexpected non-PCAP payload members in registered pcap.zip: {unexpected_payloads}')

    report = {
        'schema_version': 'v104-acquisition.2',
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
        'ignored_packaging_metadata_count': len(ignored_metadata),
        'ignored_packaging_metadata_entries': ignored_metadata,
        'packaging_metadata_policy': 'ignore only __MACOSX AppleDouble (._*) or .DS_Store central-directory entries; fail on every other non-PCAP payload',
        'member_policy': 'all 12 PCAP members are frozen for the one-shot; no PCAP selection/drop permitted',
        'next_step': 'Pin archive SHA-256 and the full sorted 12-member manifest into preregistration before any extraction or packet decode.'
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
