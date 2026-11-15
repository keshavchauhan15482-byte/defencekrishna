"""Publisher-checksummed development-source audit, never model training.

Only the predeclared development campaigns may be decoded by this command.
Raw archives stay outside Git; no archive code is executed or extracted.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import urllib.request
import zipfile

RECORD = '13168643'
DEVELOPMENT = {'fox': 'd3024ef6033fbd45982464f6b6f50984',
               'harrison': '840224491fb31d548e7ee0ecbd951db5',
               'russellmitchell': '290aa5b8b0a9d0515b7e99329c467364',
               'santos': 'e217db1c0307a8966db9e79609789fcb',
               'shaw': '25c5a62572d37f088353cf7bbd58f590'}
RESERVED = ('wardbeck', 'wheeler', 'wilson')


def inspect_zip(path):
    members, total = [], Counter()
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > 1000 or sum(i.file_size for i in infos) > 2_000_000_000:
            raise ValueError('Archive exceeds bounded data audit size')
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith('.csv'):
                continue
            counts, rows, columns = Counter(), 0, None
            with z.open(info) as raw:
                text = io.TextIOWrapper(raw, encoding='utf-8-sig', errors='strict')
                first = text.readline()
                delimiter = ';' if first.count(';') > first.count(',') else ','
                reader = csv.DictReader(itertools.chain([first], text), delimiter=delimiter)
                columns = reader.fieldnames or []
                if len(set(columns)) != len(columns): raise ValueError('Duplicate CSV headers')
                choices = [k for k in columns if k.strip().lower() in ('label', 'labels', 'class', 'attack')]
                if len(choices) != 1:
                    raise ValueError('Unambiguous publisher label column required: ' + repr(columns))
                for row in reader:
                    if None in row: raise ValueError('Malformed CSV row has extra fields')
                    rows += 1
                    if rows > 10_000_000: raise ValueError('Row audit cap exceeded')
                    value = row.get(choices[0])
                    if value is None or not value.strip(): value = '<unknown>'
                    counts[value] += 1
            total.update(counts)
            members.append(dict(name=info.filename, rows=rows, columns=columns, label_counts=dict(counts)))
    if not members: raise ValueError('No labelled CSV members found')
    return dict(members=members, rows=sum(m['rows'] for m in members), label_counts=dict(total),
                row_count_unit='exported records, not independent incidents; multi-sensor duplication not removed',
                five_stage_training_approved=False, zero_day_claim=False,
                stage_mapping='Not inferred from attack names; exact reviewed MITRE alignment still required')


def audit(campaign, cache, output):
    if campaign not in DEVELOPMENT: raise ValueError('Reserved/unknown campaigns must not be decoded')
    output, cache = Path(output), Path(cache)
    if output.exists(): raise ValueError('Audit output is immutable; choose a new path')
    cache.mkdir(parents=True,exist_ok=True)
    filename = campaign + '_netflows.zip'
    path = cache / filename
    url = f'https://zenodo.org/api/records/{RECORD}/files/{filename}/content'
    if not path.exists():
        temporary = path.with_suffix('.download')
        if temporary.exists(): raise ValueError('Partial acquisition exists; inspect before retrying')
        size = 0
        with urllib.request.urlopen(url, timeout=45) as response, temporary.open('xb') as target:
            while True:
                block = response.read(1 << 20)
                if not block: break
                size += len(block)
                if size > 80_000_000: raise ValueError('Publisher source exceeds acquisition bound')
                target.write(block)
        temporary.rename(path)
    md5, sha = hashlib.md5(), hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            md5.update(block); sha.update(block)
    if md5.hexdigest() != DEVELOPMENT[campaign]: raise ValueError('Publisher checksum mismatch')
    report = dict(schema='ait-development-source-audit-1', campaign=campaign, source_url=url,
                  publisher_md5=md5.hexdigest(), source_sha256=sha.hexdigest(),
                  archive_bytes=path.stat().st_size, reserved_campaigns_not_decoded=list(RESERVED),
                  model_training_performed=False, model_metrics=None,
                  **inspect_zip(path))
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as f: json.dump(report,f,indent=2,allow_nan=False)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign',choices=sorted(DEVELOPMENT),required=True)
    p.add_argument('--cache',required=True);p.add_argument('--output',required=True)
    a=p.parse_args(); r=audit(a.campaign,a.cache,a.output)
    print(json.dumps({k:v for k,v in r.items() if k!='members'},indent=2))


if __name__=='__main__': main()
