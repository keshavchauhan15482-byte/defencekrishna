import numpy as np

from garuda_v3.data import SCHEMA as V31_SCHEMA
from garuda_v3.model import GraphWorldModel, PS_COMPLETE_SCHEMA
from garuda_v3.ps_complete import FEATURES as PS_FEATURES, SCHEMA as PS_SCHEMA
from garuda_v3.v107_ps_complete_graph_recovery import REQUIRED_FLOW, REQUIRED_PACKET


def test_full_ps_feature_contract_is_present():
    assert PS_SCHEMA == PS_COMPLETE_SCHEMA
    assert len(PS_FEATURES) == 34
    assert (REQUIRED_FLOW | REQUIRED_PACKET).issubset(set(PS_FEATURES))


def test_old_checkpoint_schema_roundtrip_stays_compatible(tmp_path):
    m = GraphWorldModel(architecture='gnn_lstm', seed=1, decoder='residual')
    p = tmp_path / 'old.npz'
    m.save(p, {'kind': 'old'})
    loaded, meta = GraphWorldModel.load(p)
    assert loaded.schema == V31_SCHEMA
    assert loaded.f == m.f
    assert meta['kind'] == 'old'


def test_ps_complete_checkpoint_roundtrip(tmp_path):
    m = GraphWorldModel(
        architecture='gnn_lstm', feature_dim=len(PS_FEATURES), schema=PS_SCHEMA,
        seed=2, decoder='residual'
    )
    p = tmp_path / 'ps.npz'
    m.save(p, {'kind': 'ps-complete', 'packet_features_trained': True})
    loaded, meta = GraphWorldModel.load(p)
    assert loaded.schema == PS_SCHEMA
    assert loaded.f == 34
    assert meta['packet_features_trained'] is True

    x = np.zeros((2, 8, 32, 34), dtype=np.float32)
    adj = np.zeros((2, 8, 32, 32), dtype=np.float32)
    mask = np.zeros((2, 8, 32), dtype=np.float32)
    mask[:, :, :2] = 1.0
    mean, sigma, risk = loaded.forward(x, adj, mask, horizon=4)
    assert mean.data.shape == (2, 4, 34)
    assert sigma.data.shape == (2, 4, 34)
    assert risk.data.shape == (2, 4)
