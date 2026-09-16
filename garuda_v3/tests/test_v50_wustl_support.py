import unittest

try:
    import numpy as np
    import pandas as pd
    from garuda_v3 import v50_wustl_support as v50
    V50_DEPS = True
except ModuleNotFoundError:
    np = None
    pd = None
    v50 = None
    V50_DEPS = False


@unittest.skipUnless(V50_DEPS, 'V50 research deps are intentionally separate')
class V50WUSTLSupportTests(unittest.TestCase):
    def test_schema_excludes_publisher_leakage_and_labels(self):
        n = 20
        df = pd.DataFrame({
            'StartTime': pd.date_range('2026-01-01', periods=n, freq='min'),
            'LastTime': pd.date_range('2026-01-01', periods=n, freq='min'),
            'SrcAddr': ['10.0.0.1'] * n,
            'DstAddr': ['10.0.0.2'] * n,
            'sIpId': np.arange(n),
            'dIpId': np.arange(n) + 100,
            'Traffic': ['normal'] * n,
            'Sport': np.arange(n) + 1000,
            'Dport': np.arange(n) + 2000,
            'SrcPkts': np.arange(n) + 1,
            'DstPkts': np.arange(n) + 2,
            'SrcBytes': np.arange(n) + 3,
            'DstBytes': np.arange(n) + 4,
        })
        schema = v50.resolve_schema(df)
        chosen = set(schema['eligible_network_numeric_sample'])
        self.assertNotIn('sIpId', chosen)
        self.assertNotIn('dIpId', chosen)
        self.assertNotIn('Traffic', chosen)
        self.assertNotIn('StartTime', chosen)
        self.assertGreaterEqual(schema['eligible_network_numeric_count'], 6)

    def test_clean_history_future_onset_support(self):
        # 30 contiguous minutes, one novel attack begins after a clean history in test.
        minutes = pd.date_range('2026-01-01', periods=120, freq='min', tz='UTC')
        fam = [tuple() for _ in minutes]
        attack = np.zeros(len(minutes), dtype=np.int8)
        fam[110] = ('Novel',)
        attack[110] = 1
        timeline = pd.DataFrame({'minute': minutes, 'attack_now': attack, 'families': fam})
        seq = v50.build_sequences(timeline)
        masks = {k: np.zeros(len(seq['cutoff']), dtype=bool) for k in ('train','calibration','policy','test')}
        masks['test'][:] = True
        rows = {r['family']: r for r in v50.audit_support(seq, masks)}
        self.assertGreater(rows['Novel']['test_clean_history_future_positive'], 0)

    def test_row_order_is_not_timestamp_fallback(self):
        bad = pd.Series(['not-a-time'] * 20)
        with self.assertRaises(ValueError):
            v50.parse_time(bad)


if __name__ == '__main__':
    unittest.main()
