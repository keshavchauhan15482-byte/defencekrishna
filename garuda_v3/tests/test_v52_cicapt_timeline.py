import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import pandas as pd

from garuda_v3.v52_cicapt_timeline import (
    _parse_time_series,
    audit_attack_info,
    discover_attack_info,
    evaluate_warning_lead_time,
    resolve_attack_info_schema,
)


class V52TimelineTests(unittest.TestCase):
    def test_attack_info_schema_requires_timestamp_and_attack_identity(self):
        df = pd.DataFrame({
            'Attack Time': ['2023-12-01 12:00:00'],
            'Category': ['Discovery'],
            'PID': [123],
        })
        schema = resolve_attack_info_schema(df)
        self.assertEqual(schema['time'], 'Attack Time')
        self.assertEqual(schema['tactic'], 'Category')
        self.assertEqual(schema['pid'], 'PID')

    def test_time_only_requires_explicit_date(self):
        s = pd.Series(['12:15:11', '12:22:42'])
        with self.assertRaises(ValueError):
            _parse_time_series(s)
        dt, method = _parse_time_series(s, event_date='2023-12-01')
        self.assertEqual(method, 'time_of_day_plus_explicit_date')
        self.assertEqual(dt.iloc[0].isoformat(), '2023-12-01T12:15:11+00:00')

    def test_discovery_extracts_one_unique_attack_info_by_basename(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as zf:
                zf.writestr('supplementary/Attack_info.csv', 'Attack Time,Category,PID\n2023-12-01 12:00:00,Discovery,3\n')
                zf.writestr('README.md', 'test')
            out = root / 'out'
            report = discover_attack_info(archive, out)
            self.assertTrue(report['source_ready'])
            self.assertTrue((out / 'Attack_info.csv').exists())
            self.assertEqual(report['attack_info_matches'], ['supplementary/Attack_info.csv'])

    def test_audit_never_upgrades_attack_time_to_compromise_time(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / 'Attack_info.csv'
            src.write_text(
                'Attack Time,Category,Technique,PID,Status\n'
                '2023-12-01 12:00:00,Discovery,T1087,100,success\n'
            )
            report = audit_attack_info(src, root / 'audit')
            self.assertEqual(report['lead_time_claim_level'], 'attack_step_onset_only')
            self.assertFalse(report['verified_compromise_lead_time_supported'])

    def test_lead_time_counts_only_alerts_strictly_before_event(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            event = pd.Timestamp('2023-12-01T12:00:00Z')
            timeline = root / 'timeline.json'
            timeline.write_text(json.dumps({
                'events': [{
                    'row': 0,
                    'epoch': event.timestamp(),
                    'timestamp_utc': event.isoformat(),
                    'tactic': 'discovery',
                    'technique': 'T1087',
                }]
            }))
            alerts = root / 'alerts.csv'
            alerts.write_text(
                'timestamp,alert\n'
                '2023-12-01T11:55:00Z,1\n'
                '2023-12-01T12:00:00Z,1\n'
                '2023-12-01T12:01:00Z,1\n'
            )
            report = evaluate_warning_lead_time(timeline, alerts, root / 'lead')
            self.assertEqual(report['timeline_clean_warning_hits'], 1)
            self.assertEqual(report['positive_lead_seconds'], [300.0])
            self.assertFalse(report['verified_compromise_lead_time_supported'])

    def test_duplicate_attack_info_members_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as zf:
                zf.writestr('a/Attack_info.csv', 'x')
                zf.writestr('b/Attack_info.csv', 'y')
            report = discover_attack_info(archive, root / 'out')
            self.assertFalse(report['source_ready'])
            self.assertIn('ambiguous', report['blocker'])


if __name__ == '__main__':
    unittest.main()
