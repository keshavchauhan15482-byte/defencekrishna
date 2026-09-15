import tempfile
import unittest
from pathlib import Path
import numpy as np
from garuda_v3.autograd import Adam
from garuda_v3.model import GraphWorldModel,loss
from garuda_v3.data import FEATURES,convert,build_examples
from garuda_v3.security import PolicyStore

class ModelTests(unittest.TestCase):
    def data(self):
        r=np.random.default_rng(2)
        x=r.uniform(.1,.9,(2,3,4,len(FEATURES))).astype('float32');a=r.integers(0,3,(2,3,4,4)).astype('float32');m=np.ones((2,3,4),'float32')
        return x,a,m,r.uniform(0,1,(2,2,len(FEATURES))).astype('float32'),np.array([[0,1],[1,0]],dtype='float32')
    def test_full_gnn_lstm_gradient_finite_difference(self):
        model=GraphWorldModel();args=self.data();objective=loss(model,*args);objective.backward()
        for name,index in [('g1_in',(0,0)),('enc_x',(0,0)),('enc_h',(0,0)),('dec_x',(0,0)),('risk',(0,0))]:
            p=model.params[name];analytic=float(p.grad[index]);old=float(p.data[index]);eps=.003
            p.data[index]=old+eps;plus=float(loss(model,*args).data)
            p.data[index]=old-eps;minus=float(loss(model,*args).data);p.data[index]=old
            self.assertAlmostEqual(analytic,(plus-minus)/(2*eps),delta=.0003,msg=name)
    def test_node_permutation_invariance(self):
        model=GraphWorldModel();x,a,m,*_=self.data();perm=[2,0,3,1]
        before=model.forward(x,a,m,2)[2].data
        after=model.forward(x[:,:,perm],a[:,:,perm][:,:,:,perm],m[:,:,perm],2)[2].data
        np.testing.assert_allclose(before,after,atol=1e-6)
    def test_graph_edges_affect_prediction(self):
        model=GraphWorldModel();x,a,m,*_=self.data()
        self.assertGreater(float(np.max(abs(model.forward(x,a,m,2)[2].data-model.forward(x,a*0,m,2)[2].data))),1e-6)
    def test_optimizer_reduces_joint_loss(self):
        model=GraphWorldModel();args=self.data();opt=Adam(model.parameters());before=float(loss(model,*args).data)
        for _ in range(15):objective=loss(model,*args);objective.backward();opt.step()
        self.assertLess(float(loss(model,*args).data),before)
    def test_checkpoint_roundtrip(self):
        model=GraphWorldModel();x,a,m,*_=self.data()
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'checkpoint.npz';model.save(p,{'trained':True});other,meta=GraphWorldModel.load(p)
            np.testing.assert_array_equal(model.forward(x,a,m,2)[2].data,other.forward(x,a,m,2)[2].data)
    def test_future_not_consumed(self):
        model=GraphWorldModel();x,a,m,y,label=self.data()
        before=model.forward(x,a,m,2)[2].data.copy();y[:]=999;label[:]=1
        np.testing.assert_array_equal(before,model.forward(x,a,m,2)[2].data)

class DataTests(unittest.TestCase):
    def test_flow_end_time_and_host_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'a.csv';p.write_text('Timestamp,Flow Duration,Protocol,Dst Port,Tot Fwd Pkts,Label\n01/03/2018 08:00:00,20000000,6,443,2,Benign\n')
            d=convert(p);self.assertEqual(int(d['times'][0])%3600,20)
            with self.assertRaisesRegex(ValueError,'real source'):convert(p,'host')
    def test_split_disjoint(self):
        d=dict(times=np.arange(200)*10,y=np.arange(200)%2,metadata={'mode':'service','window_seconds':10,'max_nodes':32,'source_sha256':'a'})
        splits,_=build_examples([d],8,4,1);seen=[]
        for split in splits:
            ids={i for _,start in split for i in range(start,start+12)}
            self.assertTrue(all(ids.isdisjoint(s) for s in seen));seen.append(ids)
        with self.assertRaisesRegex(ValueError,'Duplicate'):build_examples([d,d])
    def test_unknown_labels_remain_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'a.csv';p.write_text('Timestamp,Flow Duration,Protocol,Dst Port,Tot Fwd Pkts\n01/03/2018 08:00:00,0,6,443,2\n')
            self.assertEqual(convert(p)['y'][0],-1)

class PolicyTests(unittest.TestCase):
    def test_scope_dry_run_and_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            store=PolicyStore(folder,allowed_cidrs=['198.51.100.0/24'])
            self.assertEqual(store.propose('198.51.100.2',30,'approved lab test')['status'],'dry_run')
            self.assertEqual(store.active(),[]);self.assertTrue(store.verify())
            with self.assertRaises(ValueError):store.propose('127.0.0.1',30,'approved test')
            with self.assertRaises(ValueError):store.propose('192.0.2.2',30,'approved test')
            store.close()
    def test_revoke_expire_kill_switch(self):
        with tempfile.TemporaryDirectory() as folder:
            store=PolicyStore(folder,key='x'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True)
            p=store.propose('198.51.100.2',30,'approved lab test');self.assertEqual(len(store.active()),1)
            store.revoke(p['id']);self.assertEqual(len(store.active()),0)
            store.propose('198.51.100.3',30,'approved lab test');store.db.execute('UPDATE policies SET expires=0');store.db.commit();store.publish();self.assertEqual(len(store.active()),0)
            store.propose('198.51.100.4',30,'approved lab test');store.kill_switch();self.assertEqual(store.active(),[]);store.close()
    def test_audit_tamper_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            store=PolicyStore(folder,allowed_cidrs=['198.51.100.0/24']);store.propose('198.51.100.2',30,'approved lab test')
            store.db.execute("UPDATE events SET payload='tampered'");store.db.commit();self.assertFalse(store.verify());store.close()

if __name__=='__main__':unittest.main()
