from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
HTML = (ROOT / 'console.html').read_text(encoding='utf-8')
CSS = (ROOT / 'garuda_v3' / 'ui' / 'console-integrated.css').read_text(encoding='utf-8')
JS = (ROOT / 'garuda_v3' / 'ui' / 'console-integrated.js').read_text(encoding='utf-8')


class PremiumConsoleEvaluatorAdditions(unittest.TestCase):
    def test_original_dashboard_contract_remains(self):
        for marker in (
            'See the threat.', 'Before the impact.', 'id="score"', 'id="threats"',
            'id="blocked"', 'id="patterns"', 'id="mutations"', 'id="traj-svg"',
            'id="feed"', 'id="attacks"', 'id="campaign"', 'id="events"',
            'id="capture-file"', 'id="analyze-file"',
        ):
            self.assertIn(marker, HTML)

    def test_evaluator_proof_is_additive(self):
        for marker in (
            'id="forecast-proof"', 'Observed history → forecast → observed future → defender decision.',
            '15.07% lower MSE', '2,209 sequences', 'OBJECTIVE PAIR PENDING',
            'V125', 'NATIVE 5-STAGE COMPOSITE PASS', 'V127/V128',
        ):
            self.assertIn(marker, HTML)

    def test_claim_boundaries_are_explicit(self):
        self.assertIn('not a verified warning before successful compromise', HTML)
        self.assertIn('not presented as proof that the V123 GNN+LSTM predicts future MITRE stages', HTML)
        self.assertIn('No synthetic compromise timestamp', HTML)

    def test_live_dual_runtime_binding_exists(self):
        self.assertIn("api('/bridge/status')", JS)
        self.assertIn('latest_state_runtime', JS)
        self.assertIn('outputs_are_not_conflated', JS)
        self.assertIn('risk_head_trained===false', JS)
        self.assertIn('stage_head_trained===false', JS)

    def test_visual_additions_use_existing_design_tokens(self):
        for marker in ('.proof-panel', '.proof-timeline', '.challenge-grid', '.evidence-strip'):
            self.assertIn(marker, CSS)
        for token in ('var(--orange)', 'var(--blue)'):
            self.assertIn(token, CSS)


if __name__ == '__main__':
    unittest.main()
