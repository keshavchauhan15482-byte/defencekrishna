import unittest
import numpy as np
from garuda_v3.v12_risk_experiment import partition,readiness,describe

class V12Tests(unittest.TestCase):
    def test_blocks_have_no_shared_windows(self):
        def graph(h):return dict(times=np.arange(500)*60,metadata=dict(source_sha256=h,mode='host',max_nodes=64,window_seconds=60,campaign_id=h))
        splits,_=partition([graph('a'),graph('b')],1)
        covered=[]
        for split in splits:
            covered.append({(source,j) for source,start in split for j in range(start,start+12)})
        for i in range(4):
            for j in range(i):self.assertFalse(covered[i]&covered[j])
        self.assertGreater(min(t for s,t in covered[1])-max(t for s,t in covered[0]),12)
        self.assertTrue(all(s==1 for s,t in covered[3]))

    def test_missing_policy_positives_blocks_readiness(self):
        enough=np.array([0]*30+[1]*30)
        r=readiness([enough,enough,np.zeros(77),enough])
        self.assertFalse(r['ready_for_supervised_policy_evaluation'])
        self.assertIn('Policy selection lacks both known classes',r['reasons'])

    def test_unknowns_never_become_benign_metrics(self):
        r=describe(np.array([-1,0,1]),np.array([1.,.1,.9]),.5)
        self.assertEqual(r['samples'],2)
        self.assertEqual(r['confusion_matrix'],[[1,0],[0,1]])

    def test_disabled_policy_cannot_be_a_successful_attack_alert(self):
        r=describe(np.array([0,1]),np.array([.9,.99]),None)
        self.assertFalse(r['policy_enabled'])
        self.assertEqual(r['recall'],0)

if __name__=='__main__':unittest.main()
