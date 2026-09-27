from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / 'garuda_v3' / 'ui'


class V128EvaluatorSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (UI / 'selection.html').read_text(encoding='utf-8')
        cls.css = (UI / 'selection.css').read_text(encoding='utf-8')
        cls.js = (UI / 'selection.js').read_text(encoding='utf-8')
        cls.server = (ROOT / 'garuda_v3' / 'server.py').read_text(encoding='utf-8')
        cls.launcher = (ROOT / 'start_local.py').read_text(encoding='utf-8')

    def test_premium_surface_is_default_runtime_page(self):
        self.assertIn("'/':('selection.html','text/html; charset=utf-8')", self.server)
        self.assertIn("'/selection.css':('selection.css','text/css')", self.server)
        self.assertIn("'/selection.js':('selection.js','application/javascript')", self.server)
        self.assertIn('PREMIUM_URL = ENGINE_URL', self.launcher)
        self.assertIn('webbrowser.open(PREMIUM_URL)', self.launcher)

    def test_judge_proof_chain_is_explicit(self):
        for text in (
            'Observed history → forecast issued → future observed → defender decision',
            '8 × 10s network graphs',
            'Future state at +10 / +20 / +30 / +40s',
            'Fresh external holdout compared with persistence',
            'Review / Arjuna / Krishna / Sudarshana',
        ):
            self.assertIn(text, self.html)

    def test_four_evaluator_challenges_are_answered_without_overclaim(self):
        self.assertIn('Attack detected, or forecast before compromise?', self.html)
        self.assertIn('Is the future attack stage predicted?', self.html)
        self.assertIn('Does a fresh checkout run end-to-end?', self.html)
        self.assertIn('What is the concrete improvement over IDS?', self.html)
        self.assertIn('Objective successful-compromise timestamp + model-warning pairing remains a separate evidence gate.', self.html)
        self.assertIn('No classifier result is presented as future-stage proof.', self.html)

    def test_v123_claim_scope_and_numbers_are_exact(self):
        self.assertIn('2,209 sequences', self.html)
        self.assertIn('15.0735%', self.html)
        self.assertIn('100%', self.html)
        self.assertIn('future network-state forecasting', self.html)
        self.assertNotIn('100% detection', self.html)
        self.assertNotIn('future-stage PASS', self.html)

    def test_live_bindings_use_real_runtime_endpoints(self):
        for endpoint in ('/api/status', '/api/replay?scenario=alert', '/api/analyze?type=pcap&mode=service'):
            self.assertIn(endpoint, self.js)
        for marker in ('latest_state_runtime', 'runtime_architecture', 'latest_state_forecast'):
            self.assertIn(marker, self.js)

    def test_javascript_syntax(self):
        subprocess.run(['node', '--check', str(UI / 'selection.js')], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
