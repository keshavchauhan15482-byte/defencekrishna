import unittest
import numpy as np
from garuda_v3.calibration import fit,apply,select_policy,interval,family_report
class CalibrationTests(unittest.TestCase):
 def test_monotone_and_finite(self):
  y=np.r_[np.zeros(40),np.ones(40)];p=np.linspace(.1,.9,80);c=fit(y,p)
  self.assertEqual(c['status'],'fitted');self.assertTrue(np.all(np.diff(apply(p,c))>=0))
 def test_insufficient_support_is_explicit(self):
  self.assertEqual(fit([0,1],[.2,.8])['status'],'insufficient_development_support')
 def test_no_useful_policy_cannot_alert_saturated_one(self):
  p=select_policy([0,1],[1.,1.]);self.assertIsNone(p['threshold']);self.assertFalse(p['confidence_gate_passed'])
 def test_small_sample_zero_fp_not_certified(self):
  p=select_policy(np.r_[np.zeros(40),np.ones(40)],np.r_[np.zeros(40),np.ones(40)])
  self.assertEqual(p['validation_fpr'],0);self.assertGreater(p['fpr_95pct'][1],.01);self.assertFalse(p['confidence_gate_passed'])
 def test_missing_class_withheld(self):self.assertIsNone(select_policy([0,0],[.1,.2])['threshold'])
 def test_invalid_input(self):
  with self.assertRaises(ValueError):fit([0,1],[.1,float('nan')])
 def test_unknown_any_horizon_is_not_benign(self):
  from garuda_v3.calibration import future_target
  np.testing.assert_array_equal(future_target([[0,-1],[0,1],[-1,1],[0,0]]),[-1,1,1,0])
 def test_unknown_bce_has_no_risk_gradient(self):
  from garuda_v3.model import GraphWorldModel,loss
  from garuda_v3.data import FEATURES
  m=GraphWorldModel();x=np.ones((1,2,3,len(FEATURES)),dtype='float32')*.1;a=np.ones((1,2,3,3),dtype='float32');mask=np.ones((1,2,3),dtype='float32')
  loss(m,x,a,mask,np.zeros((1,2,len(FEATURES)),dtype='float32'),np.full((1,2),-1,dtype='float32')).backward()
  np.testing.assert_allclose(m.params['risk'].grad,0,atol=1e-9)
