import unittest
from deployment.render.observed_index import observed_index
class ObservedIndexTests(unittest.TestCase):
    def test_baseline_measured_only(self):
        self.assertEqual([observed_index(n,0,None) for n in range(5)],[0,1,2,3,3])
    def test_denial_elevates_then_decays(self):
        self.assertGreater(observed_index(1,1,0),observed_index(1,0,None))
        self.assertGreater(observed_index(1,1,0),observed_index(1,1,200))
        self.assertLessEqual(observed_index(1000,999,0),100)
    def test_rejects_invalid(self):
        with self.assertRaises(ValueError):observed_index(1,1,301)
