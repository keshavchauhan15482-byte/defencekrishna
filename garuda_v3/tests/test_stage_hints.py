import unittest,copy,json
import numpy as np
from pathlib import Path
from garuda_v3.stage_hints import infer_stage_hint
from garuda_v3.data import FEATURES
from garuda_v3.benchmark_summary import summarize
class HintTests(unittest.TestCase):
 def graph(self):
  x=np.zeros((1,10,len(FEATURES)));x[0,0,FEATURES.index('syn_fraction')]=.8
  a=np.zeros((1,10,10));a[0,1:,0]=1
  return dict(x=x.tolist(),adj=a.tolist(),mask=[[1]*10],mode='host',node_names=['10.0.0.'+str(i+1) for i in range(10)])
 def test_scan_is_a_hint_not_ml_or_future_stage(self):
  h=infer_stage_hint(self.graph());self.assertEqual(h['tactic'],'Discovery');self.assertEqual(h['technique'],'T1046');self.assertFalse(h['ml_trained']);self.assertIsNone(h['confidence'])
 def test_syn_alone_does_not_invent_scanning(self):
  g=self.graph();g['adj']=np.zeros((1,10,10)).tolist();h=infer_stage_hint(g,True);self.assertIsNone(h['tactic']);self.assertEqual(h['title'],'Suspicious activity review')
 def test_three_seed_mean_is_recomputed_equally(self):
  b=summarize();self.assertEqual(b['seeds'],[42,7,19]);self.assertAlmostEqual(b['models']['gnn_lstm']['f1']['mean'],np.mean(b['models']['gnn_lstm']['f1']['values']));self.assertEqual(b['models']['logistic_regression']['f1']['sd'],0)
