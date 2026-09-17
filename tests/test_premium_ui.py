from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / 'garuda_v3' / 'ui'


class PremiumUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (UI / 'index.html').read_text(encoding='utf-8')
        cls.css = (UI / 'style.css').read_text(encoding='utf-8')
        cls.js = (UI / 'app.js').read_text(encoding='utf-8')

    def test_market_console_surfaces_required_panels(self):
        for required in (
            'id="riskGauge"',
            'id="activitySpark"',
            'id="benchmarkChart"',
            'id="graph"',
            'id="timeline"',
            'id="events"',
            'id="metrics"',
            'id="knownBloomSize"',
            'id="mutationBloomSize"',
        ):
            self.assertIn(required, self.html)

    def test_claim_boundaries_are_visible(self):
        self.assertIn('Recorded replay is not live customer telemetry.', self.html)
        self.assertIn('not proof of production zero-day detection', self.html)
        self.assertIn('not verified compromise lead time', self.html)
        self.assertIn('RECORDED REPLAY', self.html)

    def test_runtime_api_bindings_are_real(self):
        for endpoint in ('/api/status', '/api/response', '/api/benchmarks', '/api/replay', '/api/analyze'):
            self.assertIn(endpoint, self.js)
        self.assertIn('setInterval(()=>{if(connected&&!busy&&!document.hidden)run(refresh);},5000)', self.js)

    def test_premium_3d_and_responsive_contract(self):
        for marker in ('.orbitalScene', '.coreSphere', '.orbitalRing', '.heroGlass', '@media (max-width:820px)'):
            self.assertIn(marker, self.css)

    def test_javascript_syntax(self):
        subprocess.run(['node', '--check', str(UI / 'app.js')], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
