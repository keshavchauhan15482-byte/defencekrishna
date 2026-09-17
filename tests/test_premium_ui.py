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

    def test_market_console_surfaces_required_live_panels(self):
        for required in (
            'id="riskGauge"', 'id="activitySpark"', 'id="benchmarkChart"',
            'id="graph"', 'id="timeline"', 'id="events"', 'id="metrics"',
            'id="source"', 'id="stage"', 'id="arjunaState"',
            'id="krishnaState"', 'id="sudarshanaState"',
        ):
            self.assertIn(required, self.html)

    def test_claim_boundaries_are_visible(self):
        self.assertIn('No live customer sensor is connected.', self.html)
        self.assertIn('Forecast risk is a model score, not a verified compromise probability.', self.html)
        self.assertIn('Benchmarks, not decorative accuracy numbers.', self.html)
        self.assertIn('RECORDED REPLAY', self.html)

    def test_mock_marketing_metrics_are_not_shipped_as_product_claims(self):
        for forbidden in ('99.8%', '99.7%', 'Threats Predicted', 'Protected Endpoints', '2.4 TB', 'at National Scale'):
            self.assertNotIn(forbidden, self.html)

    def test_runtime_api_bindings_are_real(self):
        for endpoint in ('/api/status', '/api/response', '/api/benchmarks', '/api/replay', '/api/analyze'):
            self.assertIn(endpoint, self.js)
        self.assertIn('setInterval(()=>{if(connected&&!busy&&!document.hidden)run(refresh);},5000)', self.js)

    def test_approved_second_design_and_responsive_contract(self):
        for marker in ('.landingHero', '.heroRiskCard', '.garudaArt', '.dashboardGrid', '.defenceCards', '@media(max-width:930px)'):
            self.assertIn(marker, self.css)
        self.assertIn('Predicting attacks before compromise.', self.html)
        self.assertIn('class="garudaArt"', self.html)

    def test_secondary_pages_share_the_same_visual_system(self):
        for name in ('platform.html', 'technology.html', 'defence.html', 'evidence.html'):
            page = (UI / name).read_text(encoding='utf-8')
            self.assertIn('href="/style.css"', page)
            self.assertIn('class="siteHeader"', page)
            self.assertIn('class="subHero sectionShell"', page)
            self.assertIn('Garuda AI', page)

    def test_javascript_syntax(self):
        subprocess.run(['node', '--check', str(UI / 'app.js')], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
