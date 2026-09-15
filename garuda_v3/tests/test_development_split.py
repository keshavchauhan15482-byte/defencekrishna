import unittest
import numpy as np
from garuda_v3.data import development_examples
class DevelopmentSplitTests(unittest.TestCase):
 def captures(self):
  return [dict(times=np.arange(100)*60,y=np.zeros(100,dtype=int),metadata=dict(campaign_id=n,source_sha256=n,mode='host',window_seconds=60,max_nodes=64)) for n in ['web','bot','heldout']]
 def test_no_shared_windows_or_test_campaign_leakage(self):
  d=self.captures();splits,_=development_examples(d,{'development':['web','bot'],'test':['heldout'],'development_fraction':.7,'embargo_windows':12},8,4,2,True)
  windows=[{(s,w) for s,start in ids for w in range(start,start+12)} for ids in splits]
  for a,b in [(0,1),(0,2),(1,2)]:self.assertFalse(windows[a]&windows[b])
  self.assertTrue(all(s==2 for s,_ in splits[2]));self.assertTrue(all(start>=82 for _,start in splits[1]))
 def test_overlap_manifest_rejected(self):
  with self.assertRaises(ValueError):development_examples(self.captures(),{'development':['web','bot'],'test':['web','heldout']})
 def test_unknowns_never_relabelled(self):
  d=self.captures();d[0]['y'][10]=-1;m={'development':['web','bot'],'test':['heldout']}
  strict,_=development_examples(d,m);masked,_=development_examples(d,m,allow_unknown=True)
  self.assertGreater(len(masked[0]),len(strict[0]));self.assertEqual(d[0]['y'][10],-1)
