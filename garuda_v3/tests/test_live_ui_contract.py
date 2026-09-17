import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "garuda_v3" / "ui"


class _Ids(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        element_id = dict(attrs).get("id")
        if element_id:
            self.ids.append(element_id)


def test_live_console_preserves_all_javascript_bindings_and_unique_ids():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    parser = _Ids()
    parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids)), "duplicate HTML ids break live bindings"
    js_ids = set(re.findall(r"\$\(['\"]([^'\"]+)['\"]\)", js))
    missing = sorted(js_ids - set(parser.ids))
    assert not missing, f"live app.js bindings missing from reference console: {missing}"


def test_console_keeps_source_and_claim_boundaries():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert "No live customer sensor is connected" in html
    assert "Forecast risk is a model score, not a verified compromise probability" in html
    assert "Benchmarks, not decorative accuracy numbers" in html
    assert "RECORDED REPLAY" in html


def test_console_does_not_ship_mock_marketing_metrics_as_product_claims():
    html = (UI / "index.html").read_text(encoding="utf-8")
    forbidden = ("99.8%", "99.7%", "Threats Predicted", "Protected Endpoints", "2.4 TB", "at National Scale")
    for claim in forbidden:
        assert claim not in html


def test_fixed_reference_design_contract_is_present():
    html = (UI / "index.html").read_text(encoding="utf-8")
    css = (UI / "reference.css").read_text(encoding="utf-8")
    ref_js = (UI / "reference-live.js").read_text(encoding="utf-8")
    for marker in (
        'class="rHero"', 'class="rRiskCard rCard"', 'class="rEaglePanel garudaArt"',
        'class="rKpiStrip"', 'class="rDefenceCards"', 'class="rBottomGrid"',
        'id="arjunaState"', 'id="krishnaState"', 'id="sudarshanaState"', 'id="benchmarkChart"',
    ):
        assert marker in html
    for selector in (".refStage", ".rRiskCard", ".rIntelStack", ".rEaglePanel", ".rKpiStrip", ".rDefenceCards", ".rBottomGrid"):
        assert selector in css
    assert "const DESIGN_W=1365, DESIGN_H=900;" in html
    assert "drawGauge = function()" in ref_js
    assert "drawTimeline = function(f)" in ref_js
    assert "drawGraph = function()" in ref_js


def test_secondary_pages_exist_and_use_shared_design():
    for name in ("platform.html", "technology.html", "defence.html", "evidence.html"):
        page = (UI / name).read_text(encoding="utf-8")
        assert 'href="/style.css"' in page
        assert 'class="siteHeader"' in page
        assert 'class="subHero sectionShell"' in page
