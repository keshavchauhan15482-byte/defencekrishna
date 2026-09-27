from pathlib import Path

import pytest

from garuda_v3.v103_truncated_adapter_recovery import (
    V103ContractError,
    assert_not_consumed_external,
    canonical_sha256,
)


def test_mawi_name_is_quarantined_before_file_access(tmp_path):
    p = tmp_path / '200601011400.dump'
    with pytest.raises(V103ContractError, match='quarantined'):
        assert_not_consumed_external(p)


def test_hikari_name_is_quarantined_before_file_access(tmp_path):
    p = tmp_path / 'Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap'
    with pytest.raises(V103ContractError, match='quarantined'):
        assert_not_consumed_external(p)


def test_adapter_contract_hash_is_canonical():
    assert canonical_sha256({'b': 2, 'a': 1}) == canonical_sha256({'a': 1, 'b': 2})
