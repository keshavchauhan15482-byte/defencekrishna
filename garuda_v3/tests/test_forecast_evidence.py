"""Synthetic fixtures test code correctness only, never forecasting evidence."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import numpy as np
from garuda_v3.model import GraphWorldModel,loss
from garuda_v3.train import alert_threshold
from garuda_v3.annotations import annotate,STAGES
from garuda_v3.data import FEATURES,SCHEMA,save_dataset,load_dataset,campaign_examples
from garuda_v3.event_evaluation import evaluate
from garuda_v3.inference import ForecastService


def fixture(length=90,source='a'):
    rng=np.random.default_rng(4)
    return dict(x=rng.uniform(.05,.8,(length,2,len(FEATURES))).astype('float32'),
        adj=np.ones((length,2,2),dtype='float32'),mask=np.ones((length,2),dtype='float32'),
        y=np.full(length,-1,dtype='int8'),times=np.arange(length)*10,
        metadata=dict(schema=SCHEMA,source_sha256=source,campaign_id=source,mode='host',window_seconds=10,
            max_nodes=2,features=FEATURES,packet_features=True,node_names=[['192.0.2.1','192.0.2.2']]*length,synthetic=True))

class ForecastEvidenceTests(unittest.TestCase):
    def test_residual_starts_at_persistence_and_gradient_updates(self):
        d=fixture(3);x=d['x'][None];a=d['adj'][None];m=d['mask'][None]
        model=GraphWorldModel(decoder='residual');mu,_,_=model.forward(x,a,m,4)
        expected=np.repeat(x[:,-1].mean(axis=1)[:,None],4,axis=1)
        np.testing.assert_allclose(mu.data,expected,atol=1e-7)
        target=np.clip(expected+.03,0,1);args=(x,a,m,target,np.ones((1,4),dtype='float32'))
        objective=loss(model,*args);objective.backward()
        p=model.params['mean'];idx=(0,0);analytical=float(p.grad[idx]);old=float(p.data[idx]);eps=.003
        p.data[idx]=old+eps;plus=float(loss(model,*args).data)
        p.data[idx]=old-eps;minus=float(loss(model,*args).data);p.data[idx]=old
        self.assertAlmostEqual(analytical,(plus-minus)/(2*eps),delta=.0003)
        self.assertGreater(float(np.abs(p.grad).sum()),0)
    def test_unknown_stages_have_zero_stage_head_gradient(self):
        d=fixture(3);model=GraphWorldModel(decoder='residual',stage_count=5)
        args=(d['x'][None],d['adj'][None],d['mask'][None],np.full((1,2,len(FEATURES)),.3),np.ones((1,2)))
        unknown=np.full((1,2,5),-1,dtype='float32')
        loss(model,*args,stage_labels=unknown).backward()
        np.testing.assert_array_equal(model.params['stage'].grad,0)
        known=unknown.copy();known[:,:,1]=1
        loss(model,*args,stage_labels=known).backward()
        self.assertGreater(float(abs(model.params['stage'].grad[:,1]).sum()),0)
        np.testing.assert_array_equal(model.params['stage'].grad[:,[0,2,3,4]],0)
    def test_annotation_binding_unknown_boundaries_and_roundtrip(self):
        d=fixture(8)
        doc=dict(source_sha256='a',campaign_id='reviewed-lab-a',intervals=[
            dict(start=0,end=25,label=0,evidence='lab log line 1',stages={'initial_access':0}),
            dict(start=25,end=80,label=1,evidence='lab log line 2',stages={'initial_access':1})],
            incidents=[dict(incident_id='event-a',compromise_time=45,evidence='auth success log line 2')])
        out=annotate(d,doc)
        self.assertEqual(out['y'].tolist(),[0,0,-1,1,1,1,1,1])
        self.assertTrue(np.all(out['stage_y'][:,0]==-1))
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'graph.npz';save_dataset(out,p)
            np.testing.assert_array_equal(load_dataset(p)['stage_y'],out['stage_y'])
        bad=copy.deepcopy(doc);bad['source_sha256']='different'
        with self.assertRaisesRegex(ValueError,'hash'):annotate(d,bad)
        bad=copy.deepcopy(doc);bad['intervals'][1]['start']=20
        with self.assertRaisesRegex(ValueError,'Overlapping'):annotate(d,bad)
    def test_incident_misses_uncovered_and_no_post_event_alert_credit(self):
        d=fixture(20);d['y'][:]=0
        d['metadata']['incidents']=[dict(incident_id='a',compromise_time=35,evidence='fixture'),
            dict(incident_id='b',compromise_time=65,evidence='fixture'),dict(incident_id='c',compromise_time=95,evidence='fixture')]
        # First cutoff=20, compromise35: risk at +30 occurs after compromise window; no credit.
        indices=[(0,0),(0,3)];p=np.array([[.1,.1,.99],[.1,.9,.1]])
        r=evaluate([d],indices,p,2,3,.5)
        self.assertEqual(r['eligible_incidents'],2);self.assertEqual(r['detected_incidents'],1)
        self.assertEqual(r['missed_eligible_incidents'],1);self.assertEqual(r['uncovered_incidents'],1)
        self.assertEqual(r['incidents'][1]['lead_seconds'],15)
        self.assertEqual(r['clean_history_event_recall'],.5)
    def test_campaign_split_rejects_overlap_and_missing_assignment(self):
        ds=[fixture(source=c) for c in 'abc']
        for d in ds:d['y'][:]=0
        manifest={'train':['a'],'validation':['b'],'test':['c']}
        splits,_=campaign_examples(ds,manifest)
        self.assertEqual([{s for s,i in split} for split in splits],[{0},{1},{2}])
        bad={**manifest,'test':['a']}
        with self.assertRaisesRegex(ValueError,'overlap'):campaign_examples(ds,bad)
    def test_alert_threshold_requires_validation_positives_and_limits_fpr(self):
        self.assertEqual(alert_threshold([0,0],[.1,.2]),(1.0,'insufficient_validation_classes'))
        t,status=alert_threshold([0]*20+[1,1],[.1]*19+[.9,.8,.95])
        self.assertLessEqual(float((np.array([.1]*19+[.9])>=t).mean()),.05)
        self.assertEqual(status,'validation_only_fpr_budget')
    def test_annotated_host_training_to_inference_smoke(self):
        # Artificial arrays only: validate the complete training/loading/stage serving path.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=[]
            for campaign in 'abc':
                d=fixture(source=campaign);d['y']=(np.arange(90)//6%2).astype('int8')
                d['stage_y']=np.repeat(d['y'][:,None],5,axis=1)
                d['metadata']['stages']=STAGES
                d['x'][:,:,FEATURES.index('packet_features_present')]=1
                path=root/(campaign+'.npz');save_dataset(d,path);paths.append(str(path))
            manifest=root/'split.json';manifest.write_text(json.dumps(dict(train=['a'],validation=['b'],test=['c'])))
            output=root/'out'
            proc=subprocess.run([sys.executable,'-m','garuda_v3.train','--graphs',*paths,'--output',str(output),
                '--decoder','residual','--stage-supervision','--split-manifest',str(manifest),'--epochs','1','--history','3','--horizon','2','--stride','3'],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            service=ForecastService(output)
            self.assertTrue(service.meta['packet_features_trained'])
            result=service.predict(json.loads((output/'replay.json').read_text()))
            self.assertEqual(len(result['stage_trajectory']),2)
            self.assertEqual(len(result['stage_trajectory'][0]['stages']),5)
            self.assertIn('Supervised',result['stage_status'])
            self.assertFalse(result['automatic_containment'])
            # Training cannot silently replace checkpoints.
            again=subprocess.run(proc.args,capture_output=True,text=True)
            self.assertNotEqual(again.returncode,0)

if __name__=='__main__':unittest.main()
