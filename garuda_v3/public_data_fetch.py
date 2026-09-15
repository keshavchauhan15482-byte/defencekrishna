"""Reproducible additive downloads from a hash-locked, explicit data catalogue.

Never executes archive contents. Existing files must match the registered hash.
Use --extract to extract only explicitly listed CSV/PCAP members, with size limits.
"""
import argparse
import hashlib
import json
import os
import uuid
from pathlib import Path
import urllib.request
import zipfile
from .multisource import sha256


def fetch(entry, root, extract=False):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    name=entry['filename']
    if Path(name).name != name:raise ValueError('Invalid catalogue filename')
    path=root/name;temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.partial')
    if not path.exists():
        h=hashlib.sha256();size=0
        try:
            with urllib.request.urlopen(entry['url'],timeout=90) as source,temporary.open('xb') as output:
                while chunk:=source.read(1024*1024):
                    size+=len(chunk)
                    if size>entry['bytes']:raise ValueError('Source larger than pinned version')
                    h.update(chunk);output.write(chunk)
            if size!=entry['bytes'] or h.hexdigest()!=entry['sha256']:
                raise ValueError('Public source changed; review before accepting new hash')
            os.replace(temporary,path)
        finally:
            if temporary.exists():temporary.unlink()
    if path.stat().st_size!=entry['bytes'] or sha256(path)!=entry['sha256']:
        raise ValueError('Existing source differs from pinned version')
    path.with_suffix('.source.json').write_text(json.dumps(entry,indent=2))
    if extract and entry.get('members'):
        with zipfile.ZipFile(path) as archive:
            for member in entry.get('members',[]):
                info=archive.getinfo(member['name'])
                if Path(info.filename).name!=info.filename or info.file_size!=member['bytes']:
                    raise ValueError('Archive member differs from catalogue')
                target=root/info.filename;tmp=target.with_name(target.name+'.'+uuid.uuid4().hex+'.partial')
                try:
                    with archive.open(info) as src,tmp.open('xb') as dst:
                        while b:=src.read(1024*1024):dst.write(b)
                    if sha256(tmp)!=member['sha256']:raise ValueError('Extracted member hash mismatch')
                    os.replace(tmp,target)
                finally:
                    if tmp.exists():tmp.unlink()
    return str(path)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalogue',default='datasets/multisource/catalogue.json')
    p.add_argument('--root',default='datasets/multisource/raw')
    p.add_argument('--ids',nargs='+');p.add_argument('--extract',action='store_true')
    a=p.parse_args();catalogue=json.loads(Path(a.catalogue).read_text())
    selected=a.ids or list(catalogue['sources'])
    for name in selected:
        print(fetch(catalogue['sources'][name],a.root,a.extract),flush=True)


if __name__=='__main__':main()
