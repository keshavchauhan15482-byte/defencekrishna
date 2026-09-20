"""V76e support-only unseen-subtype freeze for stage generalisation.

This protocol deliberately separates two questions:
1) stage generalisation to a fine attack subtype absent from development; and
2) clean-history attack onset timing.
X-IIoTID has zero clean-onset support for its Reconnaissance subtypes under the 8+4
sequence contract, so V76e does not pretend this is an onset benchmark. It freezes one
class1 subtype per lifecycle stage using target support only. All selected subtype
exposure will be removed from V77 development data.
No model is trained or scored here.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import pandas as pd

from .v47_unseen_family import detect_label_hierarchy, norm, parse_time
from .v48_strict_runner import canonical_family_name
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import (
    MIN_DEV_PER_STAGE,
    MIN_RESERVE_PER_STAGE,
    build_minute_pairs,
    candidate_table,
    make_sequence_metadata,
    sha256,
)

MAX_CANDIDATES_PER_STAGE = 4


def choose_stage_generalisation(rows, table):
    pools = {}
    for stage in STAGES:
        eligible = [
            r for r in table[stage]
            if r["target_support"] >= MIN_RESERVE_PER_STAGE
            and r["remaining_stage_support_if_held_out_alone"][stage] >= MIN_DEV_PER_STAGE
        ][:MAX_CANDIDATES_PER_STAGE]
        if not eligible:
            raise RuntimeError(f"No support-qualified fine subtype for {stage}; candidates={table[stage][:12]}")
        pools[stage] = eligible

    best = None
    for combo in itertools.product(*(pools[s] for s in STAGES)):
        chosen = {stage: item["subtype"] for stage, item in zip(STAGES, combo)}
        reserve_pairs = {(stage, subtype) for stage, subtype in chosen.items()}
        reserve_support = {}
        development_support = {}
        for stage in STAGES:
            target_pair = (stage, chosen[stage])
            reserve_support[stage] = sum(
                1 for row in rows
                if row["target_stage"] == stage
                and row["target_subtype"] == chosen[stage]
                and target_pair in row["future_pairs"]
                and not (reserve_pairs - {target_pair}).intersection(row["all_pairs"])
            )
            development_support[stage] = sum(
                1 for row in rows
                if row["target_stage"] == stage
                and row["target_subtype"] is not None
                and not reserve_pairs.intersection(row["all_pairs"])
            )
        if not all(v >= MIN_RESERVE_PER_STAGE for v in reserve_support.values()):
            continue
        if not all(v >= MIN_DEV_PER_STAGE for v in development_support.values()):
            continue
        objective = (
            min(reserve_support.values()),
            min(development_support.values()),
            sum(reserve_support.values()),
            sum(development_support.values()),
            tuple(chosen[s] for s in STAGES),
        )
        row = {"chosen": chosen, "reserve_support": reserve_support, "development_support": development_support}
        if best is None or objective > best[0]:
            best = (objective, row)
    if best is None:
        raise RuntimeError("No five-stage unseen-subtype combination meets the support gate")
    return best[1], pools


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv',required=True); p.add_argument('--output',required=True)
    args=p.parse_args()
    csv=Path(args.csv)
    df=pd.read_csv(csv,low_memory=False)
    cols={norm(c):c for c in df.columns}
    if not {'class1','class2','class3'} <= set(cols):
        raise RuntimeError('Audited class1/class2/class3 hierarchy missing')
    dt,date_col,ts_col,time_method=parse_time(df)
    binary,family,binary_col,family_col,profiles=detect_label_hierarchy(df)
    if norm(binary_col)!='class3' or norm(family_col)!='class2':
        raise RuntimeError(f'Hierarchy drift: {binary_col}/{family_col}')
    subtype_col=cols['class1']
    family=family.map(canonical_family_name)
    minute_pairs,src_col=build_minute_pairs(df,dt,binary,family,subtype_col)
    sequences=make_sequence_metadata(minute_pairs)
    table,total_stage_support=candidate_table(sequences)
    selected,pools=choose_stage_generalisation(sequences,table)
    reserve_pairs={(stage,sub) for stage,sub in selected['chosen'].items()}
    clean_onset_support={}
    for stage,sub in selected['chosen'].items():
        pair=(stage,sub)
        clean_onset_support[stage]=int(sum(
            1 for r in sequences
            if r['target_stage']==stage and r['target_subtype']==sub and pair not in r['history_pairs']
        ))
    out={
      'protocol':'V76e support-only class1 unseen-subtype stage-generalisation freeze',
      'schema_audit_run':35527685335,
      'selection_used_model_metrics':False,
      'model_scored_reserve_before_freeze':False,
      'dataset_sha256':sha256(csv),
      'binary_label_column':binary_col,
      'lifecycle_family_column':family_col,
      'fine_subtype_column':subtype_col,
      'selected_reserve_subtype_by_stage':selected['chosen'],
      'reserve_stage_support':selected['reserve_support'],
      'clean_onset_support_diagnostic_only':clean_onset_support,
      'development_stage_support_after_all_reserves':selected['development_support'],
      'total_stage_support':total_stage_support,
      'minimum_reserve_per_stage':MIN_RESERVE_PER_STAGE,
      'minimum_development_per_stage':MIN_DEV_PER_STAGE,
      'candidate_pools':pools,
      'sequence_count':int(len(sequences)),
      'reserve_touch_sequence_count':int(sum(bool(reserve_pairs.intersection(r['all_pairs'])) for r in sequences)),
      'time':{'date_column':date_col,'timestamp_column':ts_col,'method':time_method},
      'label_profiles':profiles,
      'stage_mapping':{'Reconnaissance':'Reconnaissance','Exploitation':'Initial Access proxy','Lateral Movement':'Lateral Movement','C&C':'Command & Control','Exfiltration':'Exfiltration'},
      'evaluation_scope':'zero-development-exposure subtype stage classification/generalisation; not a clean-onset or globally prospective benchmark',
      'development_isolation_rule':'V77 must exclude every sequence touching any selected (stage,class1 subtype) pair, plus overlap-neighbour embargo, from world-model and stage-mapper development',
      'claim_boundary':'A reserve subtype may be visible in the runtime history of its test sequence. It is unseen in development, not necessarily unseen at inference time. Do not call this pre-attack onset evidence.'
    }
    path=Path(args.output); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(out,indent=2,allow_nan=False)+'\n')
    print(json.dumps({k:out[k] for k in ('dataset_sha256','selected_reserve_subtype_by_stage','reserve_stage_support','clean_onset_support_diagnostic_only','development_stage_support_after_all_reserves','total_stage_support','sequence_count')},indent=2),flush=True)

if __name__=='__main__': main()
