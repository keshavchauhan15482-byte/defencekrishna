"""Audit bundled captures; derive complete-window prefixes without changing packets.

Strict runtime parsing stays strict. Recovery is an explicit offline operation,
preserves originals, requires their recorded hash, and excludes the entire final
10-second bucket. Hash-mismatching files are quarantined, never rehashed as trusted.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from .pcap_reader import _CLASSIC, _decode_ipv4, packets


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(path, output):
    path, output = Path(path), Path(output)
    if path.resolve() == output.resolve() or output.exists():
        raise ValueError('Derivative must be new; original captures are immutable')
    provenance = json.loads(path.with_suffix(path.suffix + '.source.json').read_text())
    observed = digest(path)
    report = {'source': str(path), 'source_sha256': observed,
        'expected_sha256': provenance['sha256'], 'source_url': provenance.get('source_url'),
        'attack_labels_created': False, 'automatic_containment': False}
    if observed != provenance['sha256']:
        return {**report, 'status': 'QUARANTINED_HASH_MISMATCH', 'usable': False}
    records = []
    damage = None
    contaminated = set()
    invalid_packets = 0
    with path.open('rb') as f:
        header = f.read(24)
        if len(header) != 24 or header[:4] not in _CLASSIC:
            raise ValueError('Preparation supports classic PCAP only')
        endian, unit = _CLASSIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or linktype not in (1, 101):
            raise ValueError('Unsupported PCAP header')
        while True:
            offset = f.tell()
            record = f.read(16)
            if not record:
                break
            if len(record) != 16:
                damage = 'truncated_record_header'; break
            sec, sub, captured, original = struct.unpack(endian + 'IIII', record)
            if captured > min(262144, snaplen, original):
                damage = 'invalid_record_length'; break
            data = f.read(captured)
            if len(data) != captured:
                damage = 'truncated_packet_bytes'; break
            bucket = int((sec + sub / unit) // 10) * 10
            if records and bucket < records[-1][2]:
                raise ValueError('Non-monotone source timestamps')
            try:
                _decode_ipv4(data, original=original, timestamp=sec + sub / unit, linktype=linktype)
            except ValueError:
                contaminated.add(bucket)
                invalid_packets += 1
            records.append((offset, f.tell(), bucket))
    if not records:
        raise ValueError('No complete source records')
    # The terminal bucket is incomplete even on EOF without structural damage.
    last_bucket = records[-1][2]
    retained = [r for r in records if r[2] < last_bucket and r[2] not in contaminated]
    if not retained:
        raise ValueError('No fully closed windows')
    end = retained[-1][1]
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('rb') as src, output.open('xb') as dst:
            dst.write(header)
            for start, stop, _ in retained:
                src.seek(start)
                dst.write(src.read(stop-start))
        # Fail closed on malformed packet semantics, not just record boundaries.
        decoded = sum(1 for _ in packets(output, max_packets=len(retained) + 1))
    except Exception:
        output.unlink(missing_ok=True)
        raise
    report.update(status='AUDITED_COMPLETE_WINDOW_DERIVATIVE', usable=True,
        derivative=str(output), derivative_sha256=digest(output),
        retained_records=len(retained), decoded_ipv4_packets=decoded,
        excluded_bytes=path.stat().st_size - output.stat().st_size,
        invalid_packet_records=invalid_packets, excluded_contaminated_buckets=sorted(contaminated), excluded_terminal_bucket=last_bucket,
        structural_damage=damage, recovery_scope='complete source records; terminal and contaminated windows excluded; no packet repair or imputation',
        full_original_capture=False, timestamp_truth='network observations only; attack truth unknown')
    output.with_suffix(output.suffix + '.source.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir', type=Path, default=Path('datasets/ids2018/raw'))
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for source in sorted(args.source_dir.glob('*.pcap')):
        reports.append(prepare(source, args.output_dir / source.name))
    (args.output_dir / 'packaging_audit.json').write_text(json.dumps(reports, indent=2) + '\n')
    print(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
