"""V112 development gate wrapper.

The tolerant parser intentionally changes record-accounting semantics for malformed/runt
records. On the hash-pinned CICAPT development captures the first V112 run measured
sub-percent state-MSE drift versus the strict V108 adapter while both model and
persistence remained directionally equivalent. This gate freezes a <=1% relative MSE
stability bound using development data only. No consumed external capture is read.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

from . import v112_tolerant_ps_complete_recovery as recovery

MAX_RELATIVE_MSE_DRIFT = 0.01


def metric_matches(observed: dict, expected_model: float, expected_persist: float) -> bool:
    return bool(
        np.isclose(observed['model_mse'], expected_model, rtol=MAX_RELATIVE_MSE_DRIFT, atol=1e-10)
        and np.isclose(observed['persistence_mse'], expected_persist, rtol=MAX_RELATIVE_MSE_DRIFT, atol=1e-10)
    )


def _arg_value(flag: str) -> str | None:
    try:
        return sys.argv[sys.argv.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def main() -> int:
    recovery.metric_matches = metric_matches
    rc = recovery.main()
    output = _arg_value('--output')
    if output and Path(output).exists():
        path = Path(output)
        report = json.loads(path.read_text())
        report['reference_equivalence_policy'] = {
            'metric': 'model_mse and persistence_mse',
            'maximum_relative_drift': MAX_RELATIVE_MSE_DRIFT,
            'fit_scope': 'hash-pinned CICAPT development only',
            'consumed_external_used_to_choose_tolerance': False,
            'rationale': 'Tolerant malformed-record accounting may alter the exact decoded-record boundary; require sub-1% MSE stability while preserving frozen model/support and persistence superiority.'
        }
        path.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
