"""V124 native MITRE five-stage source audit using UWF-ZeekData22.

This development-only audit downloads publisher parquet shards from UWF-ZeekData22,
inspects the actual network-record schema, and verifies native label support for the five
PS stages: Reconnaissance, Initial Access, Lateral Movement, Command and Control, and
Exfiltration. It does not use proxies or relabel Discovery/Exploitation as required stages.

The audit is intentionally schema-discovery first. A supervised stage head is not certified
until network records carrying all five exact native labels are found and a frozen split can
be evaluated with per-stage precision/recall/F1/FPR/support.
"""
from __future__ import annotations

import argparse
import hashlib
import html.parser
import json
import re
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

BASE = "https://datasets.uwf.edu/data/UWF-ZeekData22/parquet"
WEEKS = (
    "2021-12-12 - 2021-12-19",
    "2021-12-19 - 2021-12-26",
    "2021-12-26 - 2022-01-02",
    "2022-01-02 - 2022-01-09",
    "2022-01-09 - 2022-01-16",
    "2022-01-16 - 2022-01-23",
    "2022-02-06 - 2022-02-13",
    "2022-02-13 - 2022-02-20",
)
REQUIRED = (
    "reconnaissance",
    "initial access",
    "lateral movement",
    "command and control",
    "exfiltration",
)


class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.links=[]
    def handle_starttag(self, tag, attrs):
        if tag.lower()=="a":
            href=dict(attrs).get("href")
            if href: self.links.append(href)


def get_bytes(url: str) -> bytes:
    req=urllib.request.Request(url,headers={"User-Agent":"Garuda-V124-stage-audit/1.0"})
    with urllib.request.urlopen(req,timeout=180) as r:
        return r.read()


def download(url: str, path: Path) -> None:
    req=urllib.request.Request(url,headers={"User-Agent":"Garuda-V124-stage-audit/1.0"})
    with urllib.request.urlopen(req,timeout=180) as r, path.open("wb") as f:
        while True:
            b=r.read(1024*1024)
            if not b: break
            f.write(b)


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()


def norm(s: Any) -> str:
    s=str(s or "").strip().lower()
    s=re.sub(r"[_\-]+"," ",s)
    s=re.sub(r"\s+"," ",s)
    s=s.replace("command & control","command and control")
    s=s.replace("command-and-control","command and control")
    s=s.replace("c&c","command and control")
    return s


def flatten_labels(v: Any) -> list[str]:
    if v is None: return []
    if isinstance(v,(list,tuple,set)):
        out=[]
        for x in v: out.extend(flatten_labels(x))
        return out
    if isinstance(v,dict):
        out=[]
        for x in v.values(): out.extend(flatten_labels(x))
        return out
    s=str(v).strip()
    if not s or s.lower() in {"none","null","nan","[]"}: return []
    # preserve multiword tactic names while allowing list-like encodings.
    s=s.strip("[]{}()")
    parts=re.split(r"\s*[,;|]\s*",s)
    return [norm(x.strip(" '\"")) for x in parts if x.strip(" '\"")]


def discover_parquet(week: str) -> str:
    directory=f"{BASE}/{urllib.parse.quote(week,safe='')}" + "/"
    p=LinkParser(); p.feed(get_bytes(directory).decode("utf-8","replace"))
    files=[x for x in p.links if x.endswith(".parquet")]
    if len(files)!=1:
        raise RuntimeError(f"Expected exactly one parquet shard in {week}, got {files}")
    return urllib.parse.urljoin(directory,files[0])


def scalar_py(col: pa.ChunkedArray, i: int):
    try: return col[i].as_py()
    except Exception: return None


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache-dir",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args(); args.cache_dir.mkdir(parents=True,exist_ok=True)

    shards=[]; all_columns=Counter(); type_value_counts=defaultdict(Counter)
    tactic_candidates=set(); technique_candidates=set(); native_counts=Counter(); native_rows=Counter()
    candidate_samples=defaultdict(list); row_type_candidates=set(); total_rows=0

    for n,week in enumerate(WEEKS):
        url=discover_parquet(week)
        path=args.cache_dir/f"week{n+1}.parquet"
        download(url,path)
        pf=pq.ParquetFile(path)
        schema=pf.schema_arrow
        cols=schema.names
        total_rows+=pf.metadata.num_rows
        for c in cols: all_columns[c]+=1
        for c in cols:
            lc=c.lower()
            if "tactic" in lc or ("mitre" in lc and "tech" not in lc): tactic_candidates.add(c)
            if "technique" in lc or ("mitre" in lc and "tech" in lc): technique_candidates.add(c)
            if any(k in lc for k in ("log_type","file_type","filename","zeek_type","event_type","_type")): row_type_candidates.add(c)

        wanted=sorted(tactic_candidates | technique_candidates | row_type_candidates)
        if wanted:
            table=pq.read_table(path,columns=[c for c in wanted if c in cols])
            for c in table.column_names:
                col=table[c]
                for i in range(min(len(col),20000)):
                    v=scalar_py(col,i)
                    if v is None: continue
                    sv=str(v)
                    if len(candidate_samples[c])<20 and sv not in candidate_samples[c]: candidate_samples[c].append(sv[:500])
                    if c in row_type_candidates: type_value_counts[c][sv[:200]]+=1
                if c in tactic_candidates:
                    for chunk in col.chunks:
                        for v in chunk.to_pylist():
                            labs=flatten_labels(v)
                            matched=set()
                            for lab in labs:
                                for req in REQUIRED:
                                    if lab==req:
                                        native_counts[req]+=1; matched.add(req)
                            for req in matched: native_rows[req]+=1
        shards.append({
            "week":week,"url":url,"bytes":path.stat().st_size,"sha256":sha256(path),
            "rows":pf.metadata.num_rows,"columns":cols,"row_groups":pf.metadata.num_row_groups,
        })

    coverage={stage:{"native_label_value_count":int(native_counts[stage]),"native_rows_with_label":int(native_rows[stage]),"present":bool(native_rows[stage]>0)} for stage in REQUIRED}
    all_present=all(x["present"] for x in coverage.values())
    report={
        "schema_version":"v124-source-audit.1",
        "status":"NATIVE_FIVE_STAGE_SOURCE_FOUND" if all_present else "NATIVE_FIVE_STAGE_SOURCE_INCOMPLETE",
        "dataset":"UWF-ZeekData22",
        "publisher":"University of West Florida Cyber Analytics Research Group",
        "source_base":BASE,
        "source_claim":"Publisher describes the data as network traffic/Zeek records labelled with MITRE ATT&CK via mission logs.",
        "required_exact_native_stages":list(REQUIRED),
        "proxy_mapping_used":False,
        "discovery_mapped_to_reconnaissance":False,
        "exploitation_mapped_to_initial_access":False,
        "total_rows":int(total_rows),
        "shards":shards,
        "columns_present_in_shards":dict(all_columns),
        "tactic_candidate_columns":sorted(tactic_candidates),
        "technique_candidate_columns":sorted(technique_candidates),
        "row_type_candidate_columns":sorted(row_type_candidates),
        "candidate_samples":dict(candidate_samples),
        "row_type_sample_counts":{k:dict(v.most_common(30)) for k,v in type_value_counts.items()},
        "native_stage_coverage":coverage,
        "all_five_native_labels_present":all_present,
        "next_gate":"Only if all five exact native labels exist: build a network-record-only frozen split and train/evaluate a five-class head with per-stage precision/recall/F1/FPR/support."
    }
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,indent=2,allow_nan=False)+"\n")
    print(json.dumps({"status":report["status"],"total_rows":report["total_rows"],"tactic_columns":report["tactic_candidate_columns"],"coverage":coverage},indent=2))
    return 0

if __name__=="__main__": raise SystemExit(main())
