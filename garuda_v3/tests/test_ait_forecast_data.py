import unittest
from garuda_v3.ait_forecast_data import flow, normalized


class AitForecastDataTests(unittest.TestCase):
    def row(self):
        return {'#15#c_ip:1':'192.0.2.1','s_ip:15':'192.0.2.2','s_port:16':'443',
          'first:29':'1642209150000','last:30':'1642209171000','c_pkts_all:3':'2',
          's_pkts_all:17':'3','c_bytes_all:9':'200','s_bytes_all:23':'300','label':'known'}

    def test_completed_features_enter_at_end_not_first_packet(self):
        f=flow(self.row(),'tcp',{'known':1})
        self.assertEqual(f['duration'],21)
        self.assertEqual(f['end'],1642209171)
        self.assertFalse(f['packet_present']);self.assertFalse(f['window_present'])

    def test_unknown_labels_not_made_benign_or_attack(self):
        self.assertIsNone(flow(self.row(),'tcp',{})['label'])

    def test_future_or_invalid_times_rejected(self):
        r=self.row();r['last:30']='1642209100000'
        with self.assertRaises(ValueError):flow(r,'tcp',{})
        r=self.row();r['s_port:16']='65536'
        with self.assertRaises(ValueError):flow(r,'tcp',{})

    def test_header_prefix_normalization(self):
        self.assertEqual(normalized({'#15#c_ip:1':'a','#c_ip:1':'a'}),{'c_ip':'a'})


if __name__=='__main__':unittest.main()
