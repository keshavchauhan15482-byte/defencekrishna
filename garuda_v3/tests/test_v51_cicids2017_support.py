import unittest

try:
    import numpy as np
    import pandas as pd
    from garuda_v3 import v51_cicids2017_support as v51
    V51_DEPS = True
except ModuleNotFoundError:
    np = None
    pd = None
    v51 = None
    V51_DEPS = False


@unittest.skipUnless(V51_DEPS, 'V51 research deps are intentionally separate')
class V51SupportTests(unittest.TestCase):
    def test_sequence_onset_and_clean_support(self):
        n=30
        times=pd.date_range('2017-07-07 09:00:00',periods=n,freq='10s',tz='UTC')
        fam=[tuple() for _ in range(n)]
        fam[20]=('Novel',); fam[21]=('Novel',)
        timeline=pd.DataFrame({'time':times,'families':fam})
        timeline['attack_now']=timeline['families'].map(lambda x:int(bool(x)))
        seq=v51.make_sequences(timeline)
        h,f=v51.family_presence(seq,'Novel')
        self.assertGreater(int(((~h)&f.any(1)&seq['clean']).sum()),0)

    def test_campaign_holdout_excludes_entire_test_campaign_from_dev(self):
        def seq(with_family=False):
            hist=[]; steps=[]
            for i in range(10):
                hist.append(frozenset())
                steps.append((frozenset({'Novel'}) if with_family and i==0 else frozenset(), frozenset(), frozenset(), frozenset()))
            return {'history_families':np.asarray(hist,object),'step_families':np.asarray(steps,object),'clean':np.ones(10,bool),'future_attack':np.asarray([1 if with_family and i==0 else 0 for i in range(10)],np.int8),'cutoff':np.arange(10)}
        campaigns={'A':{'sequence':seq(False)},'B':{'sequence':seq(True)}}
        rows=v51.campaign_support(campaigns)
        row=[r for r in rows if r['family']=='Novel'][0]
        self.assertEqual(row['test_campaign'],'B')
        self.assertEqual(row['development_campaigns'],['A'])
        self.assertEqual(row['development_family_free_sequences'],10)

    def test_timestamp_failure_refuses_row_order(self):
        with self.assertRaises(ValueError):
            v51.parse_time(pd.Series(['bad']*20))

if __name__=='__main__': unittest.main()
