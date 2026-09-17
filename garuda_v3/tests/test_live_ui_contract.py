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
    assert not missing, f"live app.js bindings missing from redesigned console: {missing}"


def test_console_keeps_source_and_claim_boundaries_visible():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert "No live customer sensor is connected" in html
    assert "Recorded replay is labelled as recorded replay" in html
    assert "Forecast risk is not presented as verified compromise probability" in html
    assert "Benchmarks, not decorative accuracy numbers" in html


def test_console_does_not_ship_mock_marketing_metrics_as_product_claims():
    html = (UI / "index.html").read_text(encoding="utf-8")
    forbidden = (
        "99.8%",
        "99.7%",
        "Threats Predicted",
        "Protected Endpoints",
        "2.4 TB",
        "at National Scale",
    )
    for claim in forbidden:
        assert claim not in html


def test_third_design_visual_contract_is_present():
    html = (UI / "index.html").read_text(encoding="utf-8")
    css = (UI / "style.css").read_text(encoding="utf-8")
    for marker in (
        'class="heroConsole"',
        'class="processFlow sectionShell"',
        'class="moduleGrid sectionShell"',
        'id="arjunaState"',
        'id="krishnaState"',
        'id="sudarshanaState"',
        'id="benchmarkChart"',
    ):
        assert marker in html
    for selector in (".heroConsole", ".moduleGrid", ".statusRail", "@media (max-width:930px)"):
        assert selector in css
