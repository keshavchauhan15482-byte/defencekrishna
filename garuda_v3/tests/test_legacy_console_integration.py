import unittest
from pathlib import Path

from garuda_v3 import legacy_console


class LegacyConsoleIntegrationTests(unittest.TestCase):
    def test_console_injects_integration_assets_without_replacing_legacy_ui(self):
        html = legacy_console._inject_console().decode("utf-8")
        self.assertIn('id="radar"', html)
        self.assertIn('id="traj-svg"', html)
        self.assertIn('id="gauge-svg"', html)
        self.assertIn('/console-integrated.css', html)
        self.assertIn('/console-integrated.js', html)

    def test_network_scenarios_have_explicit_known_unknown_contract(self):
        scenarios = legacy_console.SCENARIOS
        self.assertEqual(scenarios["syn_flood"]["mode"], "known")
        self.assertEqual(scenarios["port_scan"]["mode"], "known")
        self.assertEqual(scenarios["dns_tunnel"]["mode"], "unknown")
        self.assertEqual(scenarios["c2_beacon"]["mode"], "unknown")
        self.assertEqual(scenarios["clean_baseline"]["mode"], "clean")

    def test_known_variant_is_repeatable_for_exact_memory_match(self):
        a = legacy_console._variant_payload("syn_flood", 0)
        b = legacy_console._variant_payload("syn_flood", 0)
        self.assertEqual(a["x"], b["x"])
        self.assertEqual(a["data_source"], "synthetic_network_lab_known:syn_flood")
        self.assertEqual(a["schema"], b["schema"])

    def test_unknown_variant_can_be_fresh_without_breaking_schema(self):
        a = legacy_console._variant_payload("dns_tunnel", 1)
        b = legacy_console._variant_payload("dns_tunnel", 2)
        self.assertNotEqual(a["x"], b["x"])
        self.assertEqual(a["schema"], b["schema"])
        self.assertTrue(a["data_source"].startswith("synthetic_network_lab_unknown:"))

    def test_integration_js_uses_runtime_routes_not_old_web_payload_names(self):
        js = (Path(legacy_console.UI) / "console-integrated.js").read_text()
        self.assertIn("ARJUNA · REVIEWED KNOWN MEMORY", js)
        self.assertIn("KRISHNA · UNKNOWN FORECAST TRIAGE", js)
        self.assertIn("SUDARSHANA", js)
        for name in ("SYN Flood", "Port Scan", "DNS Tunnel", "C2 Beacon", "DDoS Burst", "Exfil Spike"):
            self.assertIn(name, js)
        self.assertNotIn("Every malicious attack payload", js)
        self.assertNotIn("100.0%", js)


if __name__ == "__main__":
    unittest.main()
