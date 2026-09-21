import unittest
from pathlib import Path

from garuda_v3.ui_contract import harden_ui_asset

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / 'garuda_v3' / 'ui'


class V94UiClaimContractTests(unittest.TestCase):
    def test_secondary_console_abstains_instead_of_showing_heuristic_stage(self):
        raw = (UI / 'app.js').read_text(encoding='utf-8')
        hardened = harden_ui_asset('app.js', raw)
        self.assertNotIn('Heuristic-based, not ML-trained.', hardened)
        self.assertIn('runtime_support', hardened)
        self.assertIn('UNRESOLVED / INSUFFICIENT EVIDENCE', hardened)
        self.assertIn('SHADOW_UNRESOLVED', hardened)
        self.assertIn('advisory only', hardened)

    def test_homepage_exposes_shadow_advisory_when_support_gate_is_missing(self):
        raw = (UI / 'reference-live.js').read_text(encoding='utf-8')
        hardened = harden_ui_asset('reference-live.js', raw)
        self.assertIn('runtime_support_gate', hardened)
        self.assertIn('SHADOW / ADVISORY', hardened)
        self.assertIn('runtime_support?.supported===true', hardened)
        self.assertIn('UNRESOLVED', hardened)

    def test_ui_contract_fails_closed_on_marker_drift(self):
        with self.assertRaisesRegex(RuntimeError, 'V94 UI contract marker missing'):
            harden_ui_asset('app.js', "console.log('changed UI');")
        with self.assertRaisesRegex(RuntimeError, 'V94 UI contract marker missing'):
            harden_ui_asset('reference-live.js', "console.log('changed homepage');")


if __name__ == '__main__':
    unittest.main()
