import unittest

try:
    import numpy as np
    import pandas as pd
    from garuda_v3 import v49_cic_unseen_campaign as v49
    DEPS=True
except ModuleNotFoundError:
    np=pd=v49=None;DEPS=False

@unittest.skipUnless(DEPS,'V49 research deps separate')
class V49Tests(unittest.TestCase):
    def test_fixed_release_contract(self):
        self.assertEqual(v49.WINDOW_SECONDS,10)
        self.assertEqual(v49.HISTORY,8)
        self.assertEqual(v49.HORIZON,4)
        self.assertEqual(v49.RISK_WEIGHT,0.75)
        self.assertEqual(v49.WORLD_WEIGHT,0.25)
        self.assertEqual(v49.RELEASE_FPR,0.01)
        self.assertEqual(v49.RELEASE_RECALL,0.80)

    def test_flow_schema_excludes_label_and_timestamp(self):
        n=30
        df=pd.DataFrame({
            'Timestamp':['21/02/2018 10:00:00']*n,'Label':['Benign','DDoS attack-HOIC']*15,
            'Dst Port':np.arange(n)+1,'Protocol':np.arange(n)%2+6,'Flow Duration':np.arange(n)+10,
            'Tot Fwd Pkts':np.arange(n)+2,'Tot Bwd Pkts':np.arange(n)+3,'TotLen Fwd Pkts':np.arange(n)+4,'TotLen Bwd Pkts':np.arange(n)+5,
            'Fwd Pkt Len Mean':np.arange(n)+6,'Bwd Pkt Len Mean':np.arange(n)+7,'Flow IAT Mean':np.arange(n)+8,'Flow IAT Std':np.arange(n)+9,
            'Flow IAT Max':np.arange(n)+10,'Fwd IAT Mean':np.arange(n)+11,'Bwd IAT Mean':np.arange(n)+12,'Pkt Len Mean':np.arange(n)+13,
            'Pkt Len Std':np.arange(n)+14,'Pkt Len Max':np.arange(n)+15,'SYN Flag Cnt':np.arange(n)%2,'ACK Flag Cnt':np.arange(n)%3,
            'RST Flag Cnt':np.arange(n)%4,'PSH Flag Cnt':np.arange(n)%5,'URG Flag Cnt':np.arange(n)%6,'Init Fwd Win Byts':np.arange(n)+16,
            'Init Bwd Win Byts':np.arange(n)+17,'Active Mean':np.arange(n)+18,'Idle Mean':np.arange(n)+19,
        })
        s=v49.schema_for(df)
        self.assertGreaterEqual(len(s['features']),18)
        self.assertNotIn('Label',s['features'].values())
        self.assertNotIn('Timestamp',s['features'].values())

if __name__=='__main__':unittest.main()
