import tempfile
import unittest
from pathlib import Path

try:
    import numpy as np
    import pandas as pd
    import pyarrow
    from garuda_v3.v53_cicids2017_support import (
        build_campaign,
        campaign_support,
        expected_campaign_date,
        make_sequences,
        parse_time,
        resolve_columns,
    )
    V53_DEPS = True
except ModuleNotFoundError:
    V53_DEPS = False


@unittest.skipUnless(V53_DEPS, 'V53 research deps are intentionally separate from production runtime')
class V53SupportTests(unittest.TestCase):
    def test_parquet_timestamp_and_label_are_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'Monday-campaign.parquet'
            pd.DataFrame({
                'Timestamp': pd.to_datetime(['2017-07-03T09:00:00Z']),
                'Label': ['BENIGN'],
                'Source IP': ['1.2.3.4'],
            }).to_parquet(path, index=False)
            ts, label, count = resolve_columns(path)
            self.assertEqual(ts, 'Timestamp')
            self.assertEqual(label, 'Label')
            self.assertEqual(count, 3)

    def test_timestamp_failure_refuses_row_order(self):
        bad = pd.Series(['a', 'b', 'c'])
        with self.assertRaises(ValueError):
            parse_time(bad)

    def test_mixed_valid_timestamp_formats_are_preserved(self):
        source = pd.Series([
            '2017-07-07 15:00:00+00:00',
            '2017-07-07T15:00:10Z',
            '2017-07-07 15:00:20 UTC',
        ])
        parsed = parse_time(source, expected_date='2017-07-07')
        self.assertTrue(parsed.notna().all())
        self.assertEqual(parsed.iloc[0].isoformat(), '2017-07-07T15:00:00+00:00')
        self.assertEqual(parsed.iloc[2].isoformat(), '2017-07-07T15:00:20+00:00')

    def test_ambiguous_numeric_date_uses_independent_campaign_day(self):
        # 03/07/2017 is ambiguous. Monday's known campaign date is 2017-07-03,
        # so day-first is valid and month-first must be rejected.
        source = pd.Series(['03/07/2017 09:00:00', '03/07/2017 09:00:10'])
        parsed = parse_time(source, expected_date='2017-07-03')
        self.assertTrue((parsed.dt.date == pd.Timestamp('2017-07-03').date()).all())

    def test_wrong_campaign_date_fails_closed(self):
        source = pd.Series(['03/07/2017 09:00:00', '03/07/2017 09:00:10'])
        with self.assertRaises(ValueError):
            parse_time(source, expected_date='2017-07-04')

    def test_epoch_microseconds_are_resolved_by_magnitude(self):
        source = pd.Series([1499062800000000, 1499062810000000, 1499062820000000], dtype='int64')
        parsed = parse_time(source, expected_date='2017-07-03')
        self.assertTrue(parsed.notna().all())
        self.assertEqual(parsed.iloc[1] - parsed.iloc[0], pd.Timedelta(seconds=10))
        self.assertEqual(parsed.iloc[0].date(), pd.Timestamp('2017-07-03').date())

    def test_filename_resolves_expected_campaign_date(self):
        self.assertEqual(expected_campaign_date('Thursday-WorkingHours.csv'), '2017-07-06')
        self.assertIsNone(expected_campaign_date('campaign.csv'))

    def test_clean_history_onset_support_is_counted(self):
        base = pd.Timestamp('2017-07-03T09:00:00Z')
        rows = []
        for i in range(20):
            rows.append({
                'time': base + pd.Timedelta(seconds=10 * i),
                'families': tuple() if i < 12 else ('novel attack',),
                'attack_now': 0 if i < 12 else 1,
            })
        timeline = pd.DataFrame(rows)
        seq = make_sequences(timeline)
        campaigns = {
            'test': {'sequence': seq},
            'dev': {'sequence': make_sequences(pd.DataFrame([
                {'time': base + pd.Timedelta(seconds=10 * i), 'families': tuple(), 'attack_now': 0}
                for i in range(40)
            ]))},
        }
        support = campaign_support(campaigns)
        row = next(r for r in support if r['family'] == 'novel attack')
        self.assertGreaterEqual(row['test_family_onset_positive'], 1)
        self.assertGreaterEqual(row['test_clean_history_onset_positive'], 1)
        self.assertIsNotNone(row['first_clean_history_onset_cutoff_utc'])

    def test_build_campaign_does_not_fill_missing_buckets(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'Monday-gap.parquet'
            pd.DataFrame({
                'Timestamp': pd.to_datetime([
                    '2017-07-03T09:00:00Z',
                    '2017-07-03T09:00:20Z',
                ]),
                'Label': ['BENIGN', 'BENIGN'],
            }).to_parquet(path, index=False)
            timeline, _ = build_campaign(path)
            self.assertEqual(len(timeline), 2)
            self.assertEqual((timeline['time'].iloc[1] - timeline['time'].iloc[0]).total_seconds(), 20)


if __name__ == '__main__':
    unittest.main()
