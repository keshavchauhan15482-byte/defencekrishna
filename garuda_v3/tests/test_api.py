import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from garuda_v3.server import App,Server

ARTIFACTS=Path(__file__).resolve().parents[1]/'artifacts/residual_run'
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.app=App(ARTIFACTS,self.tmp.name,'v'*40,'o'*40,allowed_cidrs=['198.51.100.0/24'])
        self.server=Server(('127.0.0.1',0),self.app)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.app.policy.close();self.tmp.cleanup()
    def request(self,path,body=None,token='v'*40,headers=None):
        h={'Authorization':'Bearer '+token};h.update(headers or {})
        req=Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers=h)
        try:
            with urlopen(req,timeout=5) as r:return r.status,r.read()
        except HTTPError as e:return e.code,e.read()
    def test_auth_and_role(self):
        self.assertEqual(self.request('/api/status',token='wrong')[0],401)
        self.assertEqual(self.request('/api/status')[0],200)
        self.assertEqual(self.request('/api/policy/create',{'target':'198.51.100.2','ttl':30,'reason':'approved lab test'})[0],403)
        status,body=self.request('/api/policy/create',{'target':'198.51.100.2','ttl':30,'reason':'approved lab test'},token='o'*40)
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['status'],'dry_run')
    def test_response_actions_require_operator(self):
        for action in ('arm','disarm','approve','escalate'):
            self.assertEqual(self.request('/api/response/'+action,{})[0],403)
        self.assertEqual(self.request('/api/response')[0],200)
        self.assertEqual(self.request('/api/response/arm',{'target':'198.51.100.2'},token='o'*40)[0],422)
    def test_large_host_replay_does_not_use_service_checkpoint(self):
        status,body=self.request('/api/replay?scenario=hosts')
        data=json.loads(body);self.assertEqual(status,200)
        self.assertEqual(sum(data['graph']['mask'][-1]),51)
        self.assertIsNone(data['forecast'])
    def test_host_and_origin_rejected(self):
        self.assertEqual(self.request('/api/status',headers={'Origin':'http://evil.invalid'})[0],403)
        self.assertEqual(self.request('/api/status',headers={'Host':'evil.invalid'})[0],403)
    def test_replay_runs_trained_model_and_explanation(self):
        status,body=self.request('/api/replay');self.assertEqual(status,200);data=json.loads(body)
        self.assertEqual(len(data['forecast']['trajectory']),4)
        self.assertTrue(data['forecast']['explanation']['feature_attributions'])
        self.assertIsNone(data['forecast']['predicted_attack_stage'])
        self.assertFalse(data['forecast']['automatic_containment'])
    def test_no_cross_client_history_or_schema_confusion(self):
        p=json.loads((ARTIFACTS/'replay.json').read_text())
        first=json.loads(self.request('/api/forecast',p)[1])['trajectory']
        bad=dict(p);bad['mode']='host';self.assertEqual(self.request('/api/forecast',bad)[0],422)
        self.assertEqual(first,json.loads(self.request('/api/forecast',p)[1])['trajectory'])
        p['times'][-1]+=5;self.assertEqual(self.request('/api/forecast',p)[0],422)
    def test_nonfinite_and_masked_edges_rejected(self):
        p=json.loads((ARTIFACTS/'replay.json').read_text());p['x'][0][0][0]=float('nan')
        self.assertEqual(self.request('/api/forecast',p)[0],422)
        p=json.loads((ARTIFACTS/'replay.json').read_text());p['adj'][0][-1][-1]=1
        self.assertEqual(self.request('/api/forecast',p)[0],422)
    def test_checkpoint_tampering_fails(self):
        import shutil
        from garuda_v3.inference import ForecastService
        with tempfile.TemporaryDirectory() as folder:
            for name in ('gnn_lstm.npz','metrics.json'):shutil.copy(ARTIFACTS/name,folder)
            with open(Path(folder)/'gnn_lstm.npz','ab') as f:f.write(b'tampered')
            with self.assertRaisesRegex(ValueError,'integrity'):ForecastService(folder)

if __name__=='__main__':unittest.main()
