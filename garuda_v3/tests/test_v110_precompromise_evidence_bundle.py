from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.v110_precompromise_evidence_bundle import BundleError, build_bundle

MODEL='a'*64


def write_jsonl(path, rows):
    path.write_text('\n'.join(json.dumps(x) for x in rows)+'\n', encoding='utf-8')


def provenance(campaigns, reused=()):
    return {
        'identity_proof_complete': True,
        'evidence_campaign_ids': list(campaigns),
        'train_campaign_ids': [],
        'validation_campaign_ids': [],
        'calibration_campaign_ids': [],
        'development_reused_campaign_ids': list(reused),
    }


class V110BundleTests(unittest.TestCase):
    def warning(self,campaign,timestamp,wid='w1'):
        return {'event_type':'model_warning','emitted_by_model':True,'campaign_id':campaign,
                'timestamp':timestamp,'model_sha256':MODEL,'warning_id':wid}

    def compromise(self,campaign,timestamp,semantics='credentialed_remote_shell'):
        return {'event_type':'successful_compromise','establishes_successful_compromise':True,
                'campaign_id':campaign,'timestamp':timestamp,'objective_success_marker':'remote shell established',
                'source_reference':'publisher-ground-truth:event-17','event_semantics':semantics}

    def run_bundle(self,warnings,compromises,prov,campaign=None):
        td=tempfile.TemporaryDirectory(); root=Path(td.name)
        wl=root/'warnings.jsonl'; cl=root/'compromises.jsonl'; pp=root/'provenance.json'; out=root/'bundle'
        write_jsonl(wl,warnings); write_jsonl(cl,compromises); pp.write_text(json.dumps(prov),encoding='utf-8')
        result=build_bundle(wl,cl,pp,out,MODEL,campaign)
        return td,result,out

    def test_valid_real_pair_uses_first_warning(self):
        td,result,out=self.run_bundle([
            self.warning('c1','2026-01-01T00:00:10Z','w1'),
            self.warning('c1','2026-01-01T00:00:20Z','w2')],
            [self.compromise('c1','2026-01-01T00:01:00Z')],provenance(['c1']))
        try:
            self.assertEqual(result['status'],'PASS')
            self.assertEqual(result['verification']['warning_event']['warning_id'],'w1')
            self.assertEqual(result['verification']['lead_time_seconds'],50.0)
            self.assertTrue((out/'warning_event.json').exists())
        finally: td.cleanup()

    def test_attack_onset_cannot_be_compromise(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); wl=root/'w'; cl=root/'c'; pp=root/'p'
            write_jsonl(wl,[self.warning('c1','2026-01-01T00:00:10Z')])
            write_jsonl(cl,[self.compromise('c1','2026-01-01T00:01:00Z','attack_onset')])
            pp.write_text(json.dumps(provenance(['c1'])),encoding='utf-8')
            with self.assertRaises(BundleError): build_bundle(wl,cl,pp,root/'out',MODEL)

    def test_reused_campaign_cannot_certify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); wl=root/'w'; cl=root/'c'; pp=root/'p'
            write_jsonl(wl,[self.warning('c1','2026-01-01T00:00:10Z')])
            write_jsonl(cl,[self.compromise('c1','2026-01-01T00:01:00Z')])
            pp.write_text(json.dumps(provenance(['c1'],['c1'])),encoding='utf-8')
            with self.assertRaises(BundleError): build_bundle(wl,cl,pp,root/'out',MODEL)

    def test_multiple_campaigns_require_explicit_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); wl=root/'w'; cl=root/'c'; pp=root/'p'
            write_jsonl(wl,[self.warning('c1','2026-01-01T00:00:10Z'),self.warning('c2','2026-01-02T00:00:10Z')])
            write_jsonl(cl,[self.compromise('c1','2026-01-01T00:01:00Z'),self.compromise('c2','2026-01-02T00:01:00Z')])
            pp.write_text(json.dumps(provenance(['c1','c2'])),encoding='utf-8')
            with self.assertRaises(BundleError): build_bundle(wl,cl,pp,root/'out',MODEL)


if __name__=='__main__': unittest.main()
