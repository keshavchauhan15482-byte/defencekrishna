import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from garuda_v3.ui_contract import harden_ui_asset

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


def test_live_console_preserves_reference_javascript_bindings_and_unique_ids():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "reference-live.js").read_text(encoding="utf-8")
    parser = _Ids(); parser.feed(html)
    assert len(parser.ids) == len(set(parser.ids)), "duplicate HTML ids break live bindings"
    js_ids = set(re.findall(r"\$\(['\"]([^'\"]+)['\"]\)", js))
    missing = sorted(js_ids - set(parser.ids))
    assert not missing, f"reference-live.js bindings missing from approved console: {missing}"


def test_console_does_not_ship_mock_marketing_metrics_as_product_claims():
    html = (UI / "index.html").read_text(encoding="utf-8")
    for claim in ("99.8%", "99.7%", "Threats Predicted", "Protected Endpoints", "2.4 TB", "at National Scale"):
        assert claim not in html


def test_approved_image_design_contract_is_present():
    html = (UI / "index.html").read_text(encoding="utf-8")
    css = (UI / "reference.css").read_text(encoding="utf-8")
    js = (UI / "reference-live.js").read_text(encoding="utf-8")
    for marker in (
        'class="hero-left"', 'class="risk-card card"', 'class="forecast-card card"',
        'class="topology-card card"', 'class="eagle-panel"', 'class="kpi-strip"',
        'class="defence-grid"', 'class="bottom-row"', 'id="gauge"', 'id="forecast"', 'id="topology"',
    ):
        assert marker in html
    for selector in (".stage", ".risk-card", ".forecast-card", ".topology-card", ".eagle-panel", ".kpi-strip", ".defence-grid", ".bottom-row"):
        assert selector in css
    assert "width:1536px;height:1024px" in css
    assert "Math.min(innerWidth/1536,innerHeight/1024)" in js
    assert "data:image/webp;base64," in html


def test_reference_runtime_endpoints_are_bound():
    js = (UI / "reference-live.js").read_text(encoding="utf-8")
    for endpoint in ("/api/status", "/api/response", "/api/benchmarks", "/api/replay", "/api/analyze"):
        assert endpoint in js


def test_secondary_pages_exist_and_use_shared_design():
    for name in ("platform.html", "technology.html", "defence.html", "evidence.html"):
        page = (UI / name).read_text(encoding="utf-8")
        assert 'href="/style.css"' in page
        assert 'class="siteHeader"' in page
        assert 'class="subHero sectionShell"' in page


def test_v94_secondary_console_abstains_instead_of_showing_heuristic_stage():
    raw = (UI / "app.js").read_text(encoding="utf-8")
    hardened = harden_ui_asset("app.js", raw)
    assert "Heuristic-based, not ML-trained." not in hardened
    assert "runtime_support" in hardened
    assert "UNRESOLVED / INSUFFICIENT EVIDENCE" in hardened
    assert "SHADOW_UNRESOLVED" in hardened
    assert "advisory only" in hardened


def test_v94_homepage_exposes_shadow_advisory_when_support_gate_is_missing():
    raw = (UI / "reference-live.js").read_text(encoding="utf-8")
    hardened = harden_ui_asset("reference-live.js", raw)
    assert "runtime_support_gate" in hardened
    assert "SHADOW / ADVISORY" in hardened
    assert "runtime_support?.supported===true" in hardened
    assert "UNRESOLVED" in hardened


def test_v94_ui_contract_fails_closed_on_marker_drift():
    with pytest.raises(RuntimeError, match="V94 UI contract marker missing"):
        harden_ui_asset("app.js", "console.log('changed UI');")
    with pytest.raises(RuntimeError, match="V94 UI contract marker missing"):
        harden_ui_asset("reference-live.js", "console.log('changed homepage');")
