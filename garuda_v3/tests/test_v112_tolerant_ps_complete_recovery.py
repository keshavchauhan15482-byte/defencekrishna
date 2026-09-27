from pathlib import Path

import pytest

from garuda_v3.ps_complete import FEATURES, SCHEMA
from garuda_v3.v112_tolerant_ps_complete_recovery import (
    V108_MODEL_SHA256,
    V108_SUPPORT_SHA256,
    V111_SHA256,
    V112ContractError,
    assert_not_consumed_external,
)


def test_ps_complete_contract_is_34_features():
    assert SCHEMA == 'garuda-observed-graph-v46-ps-complete'
    assert len(FEATURES) == 34
    for name in (
        'psh_fraction','urg_fraction','iat_variance_log','iat_max_log',
        'ttl_variance_scaled','fragment_fraction','payload_mean_log',
        'payload_variance_log','payload_max_log','unique_destination_ports_log',
        'sequential_port_transition_fraction','random_port_transition_fraction',
        'retransmission_fraction','retransmission_count_log',
    ):
        assert name in FEATURES


def test_v111_name_is_hard_quarantined():
    with pytest.raises(V112ContractError):
        assert_not_consumed_external(Path('capture_win11.pcap'))


def test_frozen_hashes_are_explicit():
    assert len(V108_MODEL_SHA256) == 64
    assert len(V108_SUPPORT_SHA256) == 64
    assert len(V111_SHA256) == 64
    assert V108_MODEL_SHA256 != V108_SUPPORT_SHA256 != V111_SHA256
