import unittest
import numpy as np
from garuda_v3.packet_recovery_v131 import label_counts,risk_diagnostic

class PacketRecoveryTests(unittest.TestCase):
    def test_unknown_future_not_benign(self):
        y=np.array([[0,0,0,0],[-1,0,0,0],[-1,1,0,0]])
        self.assertEqual(label_counts(y),{"-1":1,"0":1,"1":1})
    def test_abstaining_positive_counts_as_miss(self):
        y=np.array([[1,0,0,0],[1,0,0,0],[0,0,0,0]])
        p=np.ones_like(y,dtype=float)*.9
        d=risk_diagnostic(y,p,np.array([True,False,True]),.5)
        self.assertEqual(d["all_positive_recall"],.5)
        self.assertEqual(d["accepted_negative_fpr"],1.)
    def test_missing_threshold_no_alert(self):
        y=np.array([[1,0,0,0],[0,0,0,0]])
        d=risk_diagnostic(y,np.ones_like(y,dtype=float),np.array([True,True]),None)
        self.assertEqual(d["all_positive_recall"],0.)
