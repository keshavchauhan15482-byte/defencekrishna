from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from garuda_v3.v109_stage_certification_audit import REQUIRED_STAGES, audit


class V109StageCertificationAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(Path('garuda_v3/artifacts/certification/v97/stage_packet_manifest.json').read_text())

    def test_current_packet_gate_passes_but_stage_gate_remains_unresolved(self):
        result = audit(self.manifest)
        self.assertEqual(result['packet_feature_gate']['status'], 'PASS')
        self.assertEqual(result['five_stage_gate']['status'], 'UNRESOLVED')
        self.assertEqual(result['combined_v97_gate'], 'SHADOW_UNRESOLVED')

    def test_missing_packet_feature_fails_packet_gate(self):
        m = copy.deepcopy(self.manifest)
        m['packet_evidence']['supported_features']['payload_distribution'] = False
        result = audit(m)
        self.assertEqual(result['packet_feature_gate']['status'], 'FAIL')
        self.assertEqual(result['combined_v97_gate'], 'SHADOW_UNRESOLVED')

    def test_stage_pass_requires_validation_artifact_and_all_metrics(self):
        m = copy.deepcopy(self.manifest)
        stage = m['stage_evidence']
        stage['all_five_independently_network_validated'] = True
        stage['artifact'] = 'frozen/native-five-stage-evidence.json'
        stage['metrics'] = {
            name: {'precision': .9, 'recall': .9, 'f1': .9, 'fpr': .01, 'support': 100}
            for name in REQUIRED_STAGES
        }
        result = audit(m)
        self.assertEqual(result['five_stage_gate']['status'], 'PASS')
        self.assertEqual(result['combined_v97_gate'], 'PASS')

    def test_zero_support_cannot_pass(self):
        m = copy.deepcopy(self.manifest)
        stage = m['stage_evidence']
        stage['all_five_independently_network_validated'] = True
        stage['artifact'] = 'frozen/native-five-stage-evidence.json'
        stage['metrics'] = {
            name: {'precision': .9, 'recall': .9, 'f1': .9, 'fpr': .01, 'support': 100}
            for name in REQUIRED_STAGES
        }
        stage['metrics']['exfiltration']['support'] = 0
        self.assertEqual(audit(m)['five_stage_gate']['status'], 'UNRESOLVED')


if __name__ == '__main__':
    unittest.main()
