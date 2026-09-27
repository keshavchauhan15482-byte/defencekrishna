from pathlib import Path

import numpy as np
import pytest

from garuda_v3.data import FEATURES
from garuda_v3.support_gate import fit as fit_support_gate
from garuda_v3.v101_packet_graph_recovery import (
    EMBARGO_SEQUENCES,
    HIKARI_CAPTURE,
    RecoveryContractError,
    assert_not_quarantined,
    chronological_phase1_split,
    packet_presence,
    select_candidate,
)


def test_hikari_filename_is_quarantined_without_reading_file():
    with pytest.raises(RecoveryContractError, match="quarantined"):
        assert_not_quarantined(Path(HIKARI_CAPTURE))


def test_phase1_split_has_embargo_and_nonempty_validation():
    train, valid = chronological_phase1_split(300)
    assert train[0] == 0
    assert valid[0] - train[-1] - 1 == EMBARGO_SEQUENCES
    assert len(train) == 210
    assert len(valid) == 300 - 210 - EMBARGO_SEQUENCES


def test_candidate_selection_uses_validation_not_phase2():
    rows = {
        "42": {"validation_mse": 0.20, "phase2_mse": 0.01},
        "43": {"validation_mse": 0.10, "phase2_mse": 9.00},
        "44": {"validation_mse": 0.15, "phase2_mse": 0.02},
    }
    assert select_candidate(rows) == "43"


def test_support_fit_centers_packet_presence_from_training_only():
    n, history, nodes, features = 20, 8, 4, len(FEATURES)
    x_train = np.zeros((n, history, nodes, features), dtype=np.float32)
    x_valid = np.zeros_like(x_train)
    mask = np.ones((n, history, nodes), dtype=np.float32)
    idx = FEATURES.index("packet_features_present")
    x_train[..., idx] = 1.0
    x_valid[..., idx] = 1.0

    gate = fit_support_gate(x_train, mask, x_valid, mask)
    assert gate["center"][idx] == pytest.approx(1.0)
    assert gate["scale"][idx] >= 0.02
    assert np.isfinite(gate["threshold"])


def test_packet_presence_requires_observed_packet_graph_nodes():
    x = np.zeros((2, 8, 3, len(FEATURES)), dtype=np.float32)
    mask = np.zeros((2, 8, 3), dtype=np.float32)
    idx = FEATURES.index("packet_features_present")
    mask[:, :, :2] = 1.0
    x[:, :, :2, idx] = 1.0
    assert packet_presence(x, mask) == pytest.approx(1.0)
