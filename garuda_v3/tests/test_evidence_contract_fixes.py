import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from garuda_v3.annotations import annotate
from garuda_v3.evidence_contracts import binary_metrics, matched_binary_report, five_stage_report, audit_holdout
from garuda_v3.ps_evidence import published_comparison
from garuda_v3.verified_campaigns import validate_manifest, benign_covers, add_event


def manifest():
    return dict(campaign_id='reviewed-a', role='train', domain='lab', capture_sha256='a'*64,
                graph_path='graph.npz', start_epoch=0, end_epoch=100, timezone='UTC',
                evidence_source='publisher timeline', benign_intervals=[], events=[])


class TimelineFixTests(unittest.TestCase):
    def test_nonfinite_epochs_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf'), True):
            m = manifest(); m['end_epoch'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): validate_manifest(m)

    def test_sha_must_be_hex(self):
        m = manifest(); m['capture_sha256'] = 'z'*64
        with self.assertRaises(ValueError): validate_manifest(m)

    def test_adjacent_benign_coverage_and_gap(self):
        m = manifest()
        m['benign_intervals'] = [dict(start_epoch=a,end_epoch=b,evidence='reviewed timeline') for a,b in [(0,20),(20,40)]]
        self.assertTrue(benign_covers(m, 5, 35))
        m['benign_intervals'][1]['start_epoch'] = 21
        self.assertFalse(benign_covers(m, 5, 35))
        with self.assertRaises(ValueError): benign_covers(m, 35, 5)

    def test_attack_cannot_overlap_benign_or_string_compromise_flag(self):
        m = manifest(); m['benign_intervals'] = [dict(start_epoch=0,end_epoch=50,evidence='reviewed timeline')]
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            add_event(m,event_id='e1',epoch=20,stage='Initial Access',outcome='success',evidence='publisher log')
        with self.assertRaisesRegex(ValueError, 'boolean'):
            add_event(manifest(),event_id='e1',epoch=60,stage='Initial Access',outcome='success',evidence='publisher log',establishes_compromise='false')

    def fixture(self):
        d = dict(times=np.array([0,10,20]), y=np.array([-1,-1,-1]), metadata=dict(source_sha256='a',window_seconds=10))
        doc = dict(source_sha256='a',campaign_id='a',intervals=[dict(start=0,end=15,label=1,evidence='publisher row 3',stages={'initial_access':1})])
        return d,doc

    def test_boundary_unknown_and_per_stage_coverage(self):
        d,doc=self.fixture(); out=annotate(d,doc)
        self.assertEqual(out['y'].tolist(),[1,-1,-1])
        self.assertEqual(out['stage_y'][:,1].tolist(),[1,-1,-1])
        self.assertTrue((out['stage_y'][:,0]==-1).all())
        self.assertEqual(out['metadata']['timeline_supervision']['stage_positive_windows']['initial_access'],1)
        self.assertFalse(out['metadata']['timeline_supervision']['annotation_used_as_network_feature'])

    def test_bad_graph_or_boolean_labels_rejected(self):
        for change in ('nan','duplicate','unknown_value','bool_label','bool_stage'):
            d,doc=self.fixture()
            if change=='nan': d['times']=np.array([0,np.nan,20])
            if change=='duplicate': d['times']=np.array([0,0,20])
            if change=='unknown_value': d['y'][0]=2
            if change=='bool_label': doc['intervals'][0]['label']=True
            if change=='bool_stage': doc['intervals'][0]['stages']['initial_access']=True
            with self.subTest(change=change),self.assertRaises(ValueError): annotate(d,doc)


class MetricTests(unittest.TestCase):
    def test_real_training_report_withholds_unsupported_fpr(self):
        from garuda_v3.coupled_heads import binary_metrics as trained_metrics, select_any_horizon_threshold
        r=trained_metrics(np.array([1,1]),np.array([.9,.8]),.5)
        self.assertIsNone(r['fpr']); self.assertFalse(r['gate_passed'])
        with self.assertRaises(ValueError): select_any_horizon_threshold(np.ones((2,4)),np.ones((2,4))*.9)

    def test_real_training_manifest_rejects_exposed_final(self):
        from garuda_v3.coupled_heads import validate_manifest
        m={k:[dict(campaign_id=k,raw_source_sha256=c*64)] for k,c in [('train','a'),('validation','b'),('test','c')]}
        m['backbone_development_source_sha256']=['a'*64]
        validate_manifest(m)
        m['exposed_source_sha256']=['c'*64]
        with self.assertRaisesRegex(ValueError,'exposed'): validate_manifest(m)

    def test_confusion_metrics_and_unknowns(self):
        r=binary_metrics([1,1,0,0,-1],[1,-1,1,0,1])
        self.assertEqual((r['tp'],r['fn'],r['fp'],r['tn']),(1,1,1,1))
        self.assertEqual(r['f1'],.5); self.assertEqual(r['coverage'],.75)
        self.assertEqual(r['unknown_truth'],1)

    def test_no_negative_support_is_not_zero_fpr(self):
        self.assertIsNone(binary_metrics([1,1],[1,1])['fpr'])
        self.assertIsNone(binary_metrics([-1],[-1])['recall'])

    def test_same_input_hash_required(self):
        scores=dict(garuda=[.9,.1],logistic=[.8,.2]); thresholds=dict(garuda=.5,logistic=.5)
        r=matched_binary_report([1,0],scores,thresholds,dict(garuda='a'*64,logistic='a'*64))
        self.assertEqual(r['models']['garuda']['precision'],1)
        with self.assertRaises(ValueError): matched_binary_report([1,0],scores,thresholds,dict(garuda='a'*64,logistic='b'*64))
        scores['garuda'][0]=float('nan')
        with self.assertRaises(ValueError): matched_binary_report([1,0],scores,thresholds,dict(garuda='a'*64,logistic='a'*64))

    def test_one_stage_does_not_certify_five(self):
        r=five_stage_report([1]*20,[1]*20)
        self.assertTrue(r['per_stage']['Initial Access']['supported'])
        self.assertFalse(r['all_five_supported']); self.assertIsNone(r['five_stage_macro_f1'])

    def test_five_stage_abstentions_count_as_misses(self):
        y=np.repeat(np.arange(5),20); p=y.copy(); p[:10]=-1
        r=five_stage_report(y,p)
        self.assertEqual(r['per_stage']['Reconnaissance']['recall'],.5)
        self.assertEqual(r['confusion_matrix'][0][5],10)
        self.assertFalse(r['all_five_supported'])
        self.assertTrue(five_stage_report(y,y)['all_five_supported'])


class HoldoutTests(unittest.TestCase):
    def protocol(self):
        p={k:[dict(campaign_id=k,source_sha256=c*64)] for k,c in [('train','a'),('validation','b'),('test','c')]}
        p.update(normalization_sources=['a'*64],class_weight_sources=['a'*64],calibration_sources=['b'*64],threshold_sources=['b'*64])
        return p

    def test_clean_split_and_leakage(self):
        p=self.protocol(); self.assertTrue(audit_holdout(p)['passed'])
        p['exposed_source_sha256']=['c'*64]
        self.assertIn('final_source_already_exposed',audit_holdout(p)['reasons'])
        p=self.protocol(); p['threshold_sources']=['c'*64]
        self.assertFalse(audit_holdout(p)['passed'])
        p=self.protocol(); p['test'][0]['campaign_id']='train'
        self.assertIn('train_test_overlap',audit_holdout(p)['reasons'])


class PublishedEvidenceTests(unittest.TestCase):
    def test_published_full_metrics_remain_separate_from_runtime(self):
        r=published_comparison()
        self.assertAlmostEqual(r['metrics']['precision']['garuda'],.912083)
        self.assertAlmostEqual(r['metrics']['f1']['logistic_regression'],.576993)
        self.assertFalse(r['live_model_metrics']); self.assertFalse(r['five_stage_forecast_validation'])
        json.dumps(r,allow_nan=False)

    def test_incomplete_comparison_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'partial.md'; path.write_text('| Recall | 100% | 99% |')
            with self.assertRaises(ValueError): published_comparison(path)

    def test_same_origin_bridge_exposes_metrics_and_rejects_foreign_origin(self):
        from garuda_v3.console_routes import handle_console
        for origin,expected in [(None,200),('http://foreign.test',403)]:
            calls=[]
            handler=SimpleNamespace(path='/bridge/evidence',command='GET',headers={'Host':'127.0.0.1:8090'},
                server=SimpleNamespace(allowed_hosts={'127.0.0.1:8090'},app=object()),respond=lambda *args:calls.append(args))
            if origin: handler.headers['Origin']=origin
            self.assertTrue(handle_console(handler)); self.assertEqual(calls[0][0],expected)


if __name__=='__main__': unittest.main()
