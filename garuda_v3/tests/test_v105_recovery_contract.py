from pathlib import Path

import pytest

from garuda_v3.v105_linklayer_runt_recovery import (
    V105ContractError,
    assert_not_consumed_external,
    same_metric_block,
)


@pytest.mark.parametrize('name', [
    'HIKARI-2021.pcap',
    '200601011400-MAWI.dump',
    'ctu-idseval-6-malicious-malware-1.pcap',
    'idseval6.zip',
])
def test_consumed_external_names_are_quarantined_without_file_access(name):
    with pytest.raises(V105ContractError, match='quarantined'):
        assert_not_consumed_external(Path(name))


def test_metric_equivalence_is_exact_enough_for_no_regression_gate():
    base = {
        'model_mse': 0.009739501401782036,
        'persistence_mse': 0.01501518115401268,
        'improvement_vs_persistence': 0.35135638379033235,
        'beats_persistence': True,
    }
    assert same_metric_block(base, dict(base))
    changed = dict(base)
    changed['model_mse'] += 1e-8
    assert not same_metric_block(base, changed)


def test_boolean_gate_must_match_even_when_numeric_metrics_match():
    a = {
        'model_mse': 1.0,
        'persistence_mse': 2.0,
        'improvement_vs_persistence': 0.5,
        'beats_persistence': True,
    }
    b = dict(a)
    b['beats_persistence'] = False
    assert not same_metric_block(a, b)
