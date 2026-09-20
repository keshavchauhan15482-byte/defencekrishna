"""Single fitting contract excluding ALL reserve families; no reserve-based tuning.

A reproduction/transfer diagnostic on already exposed public families, not a fresh
holdout claim. All family evaluations use identical fitting masks for each seed.
"""
import argparse
import json
from pathlib import Path
import pandas as pd
from .v47_unseen_family import (parse_time, detect_label_hierarchy,
    choose_network_numeric_features, build_minute_state, make_sequences,
    temporal_masks, sha256)
from .v48_strict_runner import canonical_family_name, reserve_exposure_mask
from .v48_unseen_fusion import evaluate_reserve_family


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv', required=True)
    p.add_argument('--frozen-config', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--epochs', type=int, default=12)
    args = p.parse_args()
    out = Path(args.output); out.mkdir(parents=True, exist_ok=False)
    config = json.loads(Path(args.frozen_config).read_text())
    reserve = config['reserve_families']
    df = pd.read_csv(args.csv, low_memory=False)
    dt, *_ = parse_time(df)
    y, family, *_ = detect_label_hierarchy(df)
    features, _ = choose_network_numeric_features(df)
    state, names, _ = build_minute_state(df, dt, y, family.map(canonical_family_name), features)
    seq = make_sequences(state, names)
    masks, _ = temporal_masks(seq['cutoff'])
    excluded = reserve_exposure_mask(seq, reserve)
    report = {'protocol': 'V48 joint reserve deployment diagnostic',
              'fresh_unseen_claim': False, 'source_sha256': sha256(Path(args.csv)),
              'frozen_config_sha256': sha256(Path(args.frozen_config)),
              'seeds': [42, 43, 44], 'reserve_families': reserve,
              'automatic_containment': False, 'results': {}}
    for fam in reserve:
        print('JOINT RESERVE', fam, flush=True)
        report['results'][fam] = evaluate_reserve_family(seq, masks, fam, (42, 43, 44), args.epochs, config,
            export_dir=out/'runtime', feature_names=names, fitting_exclusion=excluded)
        (out/'summary.json').write_text(json.dumps(report, indent=2, allow_nan=False))
    print(json.dumps({k: v['summary'] for k, v in report['results'].items()}, indent=2), flush=True)


if __name__ == '__main__':
    main()
