from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / 'garuda_v3' / 'ui'


class PremiumUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (UI / 'index.html').read_text(encoding='utf-8')
        cls.css = (UI / 'reference.css').read_text(encoding='utf-8')
        cls.ref_js = (UI / 'reference-live.js').read_text(encoding='utf-8')

    def test_approved_dashboard_surfaces_live_panels(self):
        for required in (
            'id="gauge"', 'id="forecast"', 'id="topology"',
            'id="riskValue"', 'id="kpiRisk"', 'id="kpiNodes"',
            'id="analysisSource"', 'id="analysisModel"',
            'id="arjunaCount"', 'id="krishnaCount"', 'id="sudarshanaCount"',
            'id="mseValue"', 'id="recallValue"', 'id="captureInput"',
        ):
            self.assertIn(required, self.html)

    def test_mock_marketing_metrics_are_not_shipped_as_product_claims(self):
        for forbidden in ('99.8%', '99.7%', 'Threats Predicted', 'Protected Endpoints', '2.4 TB', 'at National Scale'):
            self.assertNotIn(forbidden, self.html)

    def test_runtime_api_bindings_are_real(self):
        for endpoint in ('/api/status', '/api/response', '/api/benchmarks', '/api/replay', '/api/analyze'):
            self.assertIn(endpoint, self.ref_js)
        self.assertIn('setInterval(()=>guarded(refresh),5000)', self.ref_js)
        self.assertIn("sessionStorage.getItem('garuda_token')", self.ref_js)

    def test_approved_image_canvas_contract(self):
        for marker in ('.stage', '.risk-card', '.forecast-card', '.topology-card', '.eagle-panel', '.kpi-strip', '.defence-grid', '.bottom-row'):
            self.assertIn(marker, self.css)
        self.assertIn('width:1536px;height:1024px', self.css)
        self.assertIn('Predicting attacks', self.html)
        self.assertIn('before compromise.', self.html)
        self.assertIn('class="eagle-panel"', self.html)
        self.assertIn('data:image/webp;base64,', self.html)
        self.assertIn('Math.min(innerWidth/1536,innerHeight/1024)', self.ref_js)

    def test_live_charts_are_canvas_rendered(self):
        for fn in ('function drawGauge()', 'function drawForecast()', 'function drawTopology()'):
            self.assertIn(fn, self.ref_js)
        for color in ('#27e6ff', '#a14cff', '#4df2c4'):
            self.assertIn(color, self.ref_js + self.css)

    def test_secondary_pages_share_the_existing_visual_system(self):
        for name in ('platform.html', 'technology.html', 'defence.html', 'evidence.html'):
            page = (UI / name).read_text(encoding='utf-8')
            self.assertIn('href="/style.css"', page)
            self.assertIn('class="siteHeader"', page)
            self.assertIn('class="subHero sectionShell"', page)
            self.assertIn('Garuda AI', page)

    def test_javascript_syntax(self):
        subprocess.run(['node', '--check', str(UI / 'reference-live.js')], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
