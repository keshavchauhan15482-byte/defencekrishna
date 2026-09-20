import unittest
import numpy as np

try:
    from garuda_v3.v55_nonlinear_joint_generalization import (
        COMPONENTS, DEV_FPR_MARGIN, POLICY_BUDGETS,
        candidate_weights, robust_objective, temporal_history_features,
    )
    HAVE=True
except ModuleNotFoundError:
    HAVE=False

@unittest.skipUnless(HAVE,'V55 research dependencies unavailable')
class V55Tests(unittest.TestCase):
    def test_temporal_features_include_flat_and_dynamics(self):
        x=np.arange(3*8*4,dtype=float).reshape(3,8,4)
        f=temporal_history_features(x)
        self.assertEqual(f.shape,(3,8*4+5*4))
        np.testing.assert_allclose(f[:,-4:],x[:,-1,:]-x[:,-2,:])

    def test_candidate_simplex_normalized_and_has_nonlinear_head(self):
        rows=candidate_weights()
        self.assertGreaterEqual(len(rows),126)
        self.assertTrue(any(r['weights']['nonlinear_temporal_transfer']>0 for r in rows))
        for r in rows:
            self.assertAlmostEqual(sum(r['weights'].values()),1.0,places=8)
            self.assertEqual(set(r['weights']),set(COMPONENTS))

    def test_policy_search_leaves_fpr_headroom(self):
        self.assertLessEqual(max(POLICY_BUDGETS),0.005)
        self.assertLess(DEV_FPR_MARGIN,0.01)

    def test_objective_prefers_more_margin_safe_gate_folds(self):
        a=[{'state_gate_passed':True,'fpr':0.006,'recall':0.82},
           {'state_gate_passed':True,'fpr':0.007,'recall':0.83}]
        b=[{'state_gate_passed':True,'fpr':0.006,'recall':0.95},
           {'state_gate_passed':True,'fpr':0.009,'recall':0.95}]
        self.assertGreater(robust_objective(a),robust_objective(b))

if __name__=='__main__': unittest.main()
