from __future__ import annotations

import hashlib
import json
import shutil
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

OUT = Path("artifacts/toniot_onset_audit")
OUT.mkdir(parents=True, exist_ok=True)
CACHE = Path("artifacts/source_cache")
CACHE.mkdir(parents=True, exist_ok=True)
ZENODO_URL = "https://zenodo.org/records/19367312/files/Ton_Iot.zip?download=1"
ZENODO_EXPECTED_MD5 = "fd9607905ec11c4a4ff6c57c43f83ffa"
TARGET_FILES = {
    "scanning": "Network_dataset_1.csv",
    "dos": "Network_dataset_10.csv",
}
MIN_HISTORY_SECONDS = 8 * 60


def digest(path: Path, algo="md5"):
    h=hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def acquire():
    zpath=CACHE/"Ton_Iot.zip"
    extract=CACHE/"ton_iot"
    if not zpath.exists():
        req=urllib.request.Request(ZENODO_URL,headers={"User-Agent":"KrishnaDefence-V25/1.0"})
        with urllib.request.urlopen(req,timeout=180) as r,zpath.open("wb") as f:
            shutil.copyfileobj(r,f,length=8*1024*1024)
    got=digest(zpath)
    if got!=ZENODO_EXPECTED_MD5:
        raise RuntimeError(f"ToN-IoT archive MD5 mismatch {got}")
    if not extract.exists():
        extract.mkdir(parents=True)
        with zipfile.ZipFile(zpath) as z:z.extractall(extract)
    return zpath,extract


def parse_ts(s):
    x=pd.to_numeric(s,errors="coerce")
    return x


def audit_file(path:Path,target:str):
    use=["ts","src_ip","dst_ip","dst_port","proto","service","duration","src_bytes","dst_bytes","src_pkts","dst_pkts","label","type"]
    header=list(pd.read_csv(path,nrows=0).columns)
    missing=[c for c in use if c not in header]
    if missing:
        raise RuntimeError(f"{path.name} missing {missing}; columns={header}")
    first_ts=None; last_ts=None; last_attack=False; recent=[]; events=[]; family_counts=Counter(); rows=0
    # Keep only an 8-minute rolling label history; model-feature values are not
    # consulted here, so this is a support/chronology audit rather than model tuning.
    for ch in pd.read_csv(path,usecols=["ts","label","type"],chunksize=100_000,low_memory=False):
        ts=parse_ts(ch["ts"]).to_numpy(float)
        lab=pd.to_numeric(ch["label"],errors="coerce").fillna(0).astype(int).to_numpy()
        typ=ch["type"].fillna("normal").astype(str).str.strip().str.lower().to_numpy()
        order=np.argsort(ts,kind="stable")
        for j in order:
            t=float(ts[j]); y=int(lab[j]); fam=str(typ[j]); rows+=1
            if not np.isfinite(t):continue
            first_ts=t if first_ts is None else min(first_ts,t); last_ts=t if last_ts is None else max(last_ts,t)
            family_counts[fam]+=1
            while recent and recent[0][0] < t-MIN_HISTORY_SECONDS:
                recent.pop(0)
            is_target=bool(y==1 and fam==target)
            prev_target=last_attack
            if is_target and not prev_target:
                history_complete=bool(recent and recent[0][0] <= t-MIN_HISTORY_SECONDS+5)
                benign_history=history_complete and all(v==0 for _,v in recent)
                events.append({"onset_ts":t,"history_rows":len(recent),"history_complete":history_complete,"clean_8min_history":benign_history})
            recent.append((t,int(y!=0)))
            last_attack=is_target
    clean=[e for e in events if e["clean_8min_history"]]
    return {"file":str(path),"size_bytes":path.stat().st_size,"target_family":target,"rows":rows,"time_min":first_ts,"time_max":last_ts,"span_seconds":None if first_ts is None else last_ts-first_ts,"family_counts":dict(family_counts),"onset_event_n":len(events),"clean_8min_onset_event_n":len(clean),"clean_events":clean[:100],"ready":len(clean)>=1}


def main():
    zpath,root=acquire()
    report={"schema":"krishna-v25-toniot-onset-audit-v1","archive_md5":digest(zpath),"minimum_clean_history_seconds":MIN_HISTORY_SECONDS,"targets":{}}
    for fam,name in TARGET_FILES.items():
        matches=list(root.rglob(name))
        if len(matches)!=1:raise RuntimeError(f"Expected one {name}, found {len(matches)}")
        print(f"AUDIT {fam} {matches[0]}",flush=True)
        r=audit_file(matches[0],fam); report["targets"][fam]=r; print(json.dumps(r,indent=2),flush=True)
    report["ready_for_v25_world_model"]=all(x["ready"] for x in report["targets"].values())
    (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    (OUT/"REPORT.md").write_text("# V25 ToN-IoT clean-onset support audit\n\n```json\n"+json.dumps(report,indent=2)+"\n```\n",encoding="utf-8")
    if not report["ready_for_v25_world_model"]:raise RuntimeError("ToN-IoT targets lack clean 8-minute onset support")

if __name__=="__main__":main()
