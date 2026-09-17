from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "garuda_v3" / "ui"


class ApprovedReferenceDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (UI / "index.html").read_text(encoding="utf-8")
        cls.css = (UI / "pixel.css").read_text(encoding="utf-8")
        cls.js = (UI / "app.js").read_text(encoding="utf-8")

    def test_reference_visual_layer_is_loaded_after_base_css(self):
        self.assertLess(self.html.index('/style.css'), self.html.index('/pixel.css'))
        self.assertIn('class="refPage"', self.html)

    def test_reference_four_column_hero_geometry_is_locked(self):
        self.assertIn('grid-template-columns:350px 285px 315px 1fr', self.css)
        self.assertIn('grid-template-rows:317px 55px', self.css)
        self.assertIn('grid-column:1/3;grid-row:2', self.css)
        self.assertIn('grid-column:4;grid-row:1/3', self.css)

    def test_reference_eagle_asset_is_real_not_generic_svg(self):
        self.assertIn('data:image/webp;base64,', self.css)
        self.assertIn('body.refPage .garudaArt:before', self.css)
        self.assertIn('CURRENTLY ANALYSING', self.html)

    def test_live_reference_panels_keep_real_runtime_ids(self):
        for element_id in (
            'riskGauge', 'gaugeValue', 'timeline', 'graph', 'nodeCount', 'horizon',
            'responseMode', 'audit', 'events', 'benchmarkChart', 'arjunaState',
            'krishnaState', 'sudarshanaState', 'source', 'graphType', 'healthState'
        ):
            self.assertRegex(self.html, rf'id="{re.escape(element_id)}"')

    def test_reference_sections_match_approved_dashboard_structure(self):
        for marker in (
            'AI-BASED NETWORK ATTACK FORECASTING',
            'Predicting attacks<br>before compromise.',
            'Three-Layer Defence System',
            'RECENT ALERTS',
            'DATASET & EVIDENCE',
            'MODEL PERFORMANCE (CURRENT)',
            'LIVE SESSION CONTROL',
        ):
            self.assertIn(marker, self.html)

    def test_no_mock_reference_metrics_are_hardcoded(self):
        for forbidden in ('99.8%', 'Protected Endpoints', '2.4 TB', '12 Nodes', '18 Connections'):
            self.assertNotIn(forbidden, self.html)


if __name__ == '__main__':
    unittest.main()
