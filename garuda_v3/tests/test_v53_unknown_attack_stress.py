import unittest

import numpy as np

from garuda_v3.v53_unknown_attack_stress import (
    clean_onset_events,
    group_holdout_split,
)


class V53UnknownAttackStressTests(unittest.TestCase):
    def test_group_holdout_removes_selected_families_from_development(self):
        n = 80
        cutoff = np.arange(n, dtype=np.int64) * 60
        histories = np.asarray([frozenset() for _ in range(n)], dtype=object)
        steps = []
        for i in range(n):
            if i == 20:
                steps.append((frozenset({'exploitation'}), frozenset(), frozenset(), frozenset()))
            elif i == 55:
                steps.append((frozenset({'c&c'}), frozenset(), frozenset(), frozenset()))
            else:
                steps.append((frozenset(), frozenset(), frozenset(), frozenset()))
        sequences = {
            'cutoff': cutoff,
            'history_families': histories,
            'step_families': np.asarray(steps, dtype=object),
            'clean': np.ones(n, dtype=bool),
            'y': np.zeros(n, dtype=np.int8),
        }
        time_masks = {
            'train': np.arange(n) < 35,
            'calibration': (np.arange(n) >= 35) & (np.arange(n) < 50),
            'policy': (np.arange(n) >= 50) & (np.arange(n) < 65),
            'test': np.arange(n) >= 65,
        }
        split = group_holdout_split(sequences, time_masks, {'exploitation', 'c&c'})
        self.assertFalse(split['train'][20])
        self.assertFalse(split['policy'][55])
        self.assertTrue(split['holdout_touched'][20])
        self.assertTrue(split['holdout_touched'][55])
        self.assertTrue(split['overlap_blocked'][21])

    def test_clean_onset_event_uses_earliest_firing_forecast(self):
        sequences = {
            'cutoff': np.asarray([1000, 1060, 1120, 1180], dtype=np.int64),
            'clean': np.asarray([True, True, True, True]),
            'history_families': np.asarray([frozenset(), frozenset(), frozenset(), frozenset()], dtype=object),
            'step_families': np.asarray([
                (frozenset(), frozenset(), frozenset(), frozenset({'ransomware'})),
                (frozenset(), frozenset(), frozenset({'ransomware'}), frozenset()),
                (frozenset(), frozenset({'ransomware'}), frozenset(), frozenset()),
                (frozenset({'ransomware'}), frozenset(), frozenset(), frozenset()),
            ], dtype=object),
        }
        src = np.asarray(['host-a'] * 4, dtype=object)
        score = np.asarray([0.2, 0.9, 0.8, 0.1])
        summary, events = clean_onset_events(sequences, src, 'ransomware', score, threshold=0.5)
        self.assertEqual(summary['event_support'], 1)
        self.assertEqual(summary['warning_hits'], 1)
        self.assertEqual(summary['event_recall'], 1.0)
        self.assertEqual(summary['lead_seconds']['max'], 180.0)
        self.assertEqual(events[0]['first_warning_cutoff_epoch'], 1060)

    def test_clean_onset_requires_attack_free_history(self):
        sequences = {
            'cutoff': np.asarray([1000], dtype=np.int64),
            'clean': np.asarray([False]),
            'history_families': np.asarray([frozenset({'tampering'})], dtype=object),
            'step_families': np.asarray([
                (frozenset({'exploitation'}), frozenset(), frozenset(), frozenset()),
            ], dtype=object),
        }
        summary, events = clean_onset_events(
            sequences, np.asarray(['host-a'], dtype=object), 'exploitation', np.asarray([0.99]), threshold=0.5
        )
        self.assertEqual(summary['event_support'], 0)
        self.assertEqual(events, [])


if __name__ == '__main__':
    unittest.main()
