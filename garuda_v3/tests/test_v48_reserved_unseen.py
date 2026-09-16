import unittest

try:
    import numpy as np
    from garuda_v3.v48_reserved_unseen import (
        DEV_FAMILIES,
        RESERVE_FAMILIES,
        WORLD_CANDIDATES,
        HYBRID_CANDIDATES,
        empirical_surprise,
        choose_candidate,
    )
    V48_DEPS = True
except ModuleNotFoundError:
    np = None
    V48_DEPS = False


@unittest.skipUnless(V48_DEPS, 'V48 research dependencies are intentionally separate')
class V48ReservedUnseenTests(unittest.TestCase):
    def test_reserve_families_are_not_development_families(self):
        self.assertTrue(set(DEV_FAMILIES).isdisjoint(set(RESERVE_FAMILIES)))
        self.assertEqual(RESERVE_FAMILIES, ('C&C', 'Exploitation'))

    def test_empirical_surprise_is_monotone_for_high_signal(self):
        ref = np.arange(1, 101, dtype=float)
        score = empirical_surprise(ref, np.asarray([10.0, 50.0, 90.0, 110.0]))
        self.assertTrue(np.all(np.diff(score) >= 0))
        self.assertGreater(score[-1], score[0])

    def test_candidate_selection_uses_declared_lexicographic_rule(self):
        names = ('a', 'b')
        dev = {
            'fam1': {'seeds': {
                '42': {'status': 'evaluated', 'scores': {
                    'a': {'test': {'recall': .70, 'fpr': .005}},
                    'b': {'test': {'recall': .95, 'fpr': .03}},
                }},
                '43': {'status': 'evaluated', 'scores': {
                    'a': {'test': {'recall': .72, 'fpr': .005}},
                    'b': {'test': {'recall': .95, 'fpr': .03}},
                }},
            }},
            'fam2': {'seeds': {
                '42': {'status': 'evaluated', 'scores': {
                    'a': {'test': {'recall': .65, 'fpr': .006}},
                    'b': {'test': {'recall': .99, 'fpr': .02}},
                }},
                '43': {'status': 'evaluated', 'scores': {
                    'a': {'test': {'recall': .66, 'fpr': .006}},
                    'b': {'test': {'recall': .99, 'fpr': .02}},
                }},
            }},
        }
        selected, rows = choose_candidate(dev, names)
        self.assertEqual(selected, 'a')
        by_name = {r['candidate']: r for r in rows}
        self.assertEqual(by_name['a']['gate_family_count'], 2)
        self.assertEqual(by_name['b']['gate_family_count'], 0)

    def test_declared_candidate_sets_do_not_overlap(self):
        self.assertTrue(set(WORLD_CANDIDATES).isdisjoint(set(HYBRID_CANDIDATES)))


if __name__ == '__main__':
    unittest.main()
