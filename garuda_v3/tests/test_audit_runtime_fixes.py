import hashlib
import json
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import numpy as np

from garuda_v3.bundle_manifest import resolve_active_bundle
from garuda_v3.coupled_heads import attach_heads, objective, validate_manifest, HEAD_KEYS
from garuda_v3.autograd import Adam
from garuda_v3.integrated_server import IntegratedApp, IntegratedHandler
from garuda_v3.latest_state_runtime import LatestStateForecastService
from garuda_v3.pcap_packaging import prepare
from garuda_v3.server import Server

ROOT = Path(__file__).resolve().parents[2]


def capture(path, corrupt_tail=False, malformed_window=False):
    # Raw IPv4 ICMP records. No attack labels or compromise events are invented.
    packet = b'\x45\x00\x00\x14' + b'\x00'*4 + b'\x40\x01\x00\x00' + b'\x0a\x00\x00\x01\x0a\x00\x00\x02'
    header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII',2,4,0,0,65535,101)
    raw = header
    for sec in (0,10,20,30):
        p = b'\x45\x00\x00\x0a' + packet[4:] if sec == 10 and malformed_window else packet
        raw += struct.pack('<IIII',sec,0,len(p),len(p))+p
    if corrupt_tail: raw += struct.pack('<IIII',31,0,20,20)+b'x'
    path.write_bytes(raw)
    path.with_suffix('.pcap.source.json').write_text(json.dumps({'sha256':hashlib.sha256(raw).hexdigest()}))
    return raw


class PackagingTests(unittest.TestCase):
    def test_truncated_tail_excludes_whole_last_bucket_preserves_source(self):
        with tempfile.TemporaryDirectory() as td:
            p, out = Path(td)/'raw.pcap', Path(td)/'prepared.pcap'
            raw = capture(p, corrupt_tail=True)
            r = prepare(p, out)
            self.assertEqual(r['retained_records'],3)
            self.assertEqual(r['excluded_terminal_bucket'],30)
            self.assertEqual(r['structural_damage'],'truncated_packet_bytes')
            self.assertEqual(p.read_bytes(),raw)
            self.assertFalse(r['attack_labels_created'])

    def test_invalid_packet_excludes_entire_window(self):
        with tempfile.TemporaryDirectory() as td:
            p, out = Path(td)/'raw.pcap', Path(td)/'prepared.pcap'
            capture(p, malformed_window=True)
            r = prepare(p,out)
            self.assertEqual(r['excluded_contaminated_buckets'],[10])
            self.assertEqual(r['retained_records'],2)

    def test_hash_mismatch_never_creates_derivative(self):
        with tempfile.TemporaryDirectory() as td:
            p, out = Path(td)/'raw.pcap', Path(td)/'prepared.pcap'
            capture(p);p.write_bytes(p.read_bytes()+b'x')
            self.assertEqual(prepare(p,out)['status'],'QUARANTINED_HASH_MISMATCH')
            self.assertFalse(out.exists())


class CoupledHeadTests(unittest.TestCase):
    def test_training_changes_heads_only(self):
        runtime = LatestStateForecastService(); model = attach_heads(runtime.model,42)
        x=np.zeros((2,8,32,34),np.float32);mask=np.zeros((2,8,32),np.float32)
        x[:,:,0,:]=.1;mask[:,:,0]=1
        d={'x':x,'adj':np.zeros((2,8,32,32),np.float32),'mask':mask,
           'risk_y':np.array([[0,0,0,0],[1,1,1,1]]),
           'stage_y':np.array([[-1,-1,-1,-1],[0,1,2,3]])}
        before={k:v.data.copy() for k,v in model.params.items()}
        loss=objective(model,d,np.arange(2));self.assertTrue(np.isfinite(loss.data))
        loss.backward();Adam([model.params[k] for k in HEAD_KEYS],lr=.003).step()
        self.assertTrue(any(not np.array_equal(before[k],model.params[k].data) for k in HEAD_KEYS))
        for k in before:
            if k not in HEAD_KEYS:self.assertTrue(np.array_equal(before[k],model.params[k].data))

    def test_campaign_or_raw_source_overlap_is_rejected(self):
        entry={'campaign_id':'a','raw_source_sha256':'a'*64}
        manifest={s:[entry.copy()] for s in ('train','validation','test')}
        with self.assertRaises(ValueError):validate_manifest(manifest)


class UnifiedConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.app=IntegratedApp(resolve_active_bundle(ROOT),Path(cls.tmp.name),'r'*32,'o'*32)
        cls.server=Server(('127.0.0.1',0),cls.app);cls.server.RequestHandlerClass=IntegratedHandler
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.app.policy.close();cls.tmp.cleanup()

    def request(self,path,body=None,headers=None):
        req=urllib.request.Request(self.base+path,data=None if body is None else json.dumps(body).encode(),headers=headers or {})
        try:
            with urllib.request.urlopen(req,timeout=15) as r:return r.status,r.read(),r.headers
        except urllib.error.HTTPError as e:return e.code,e.read(),e.headers

    def test_same_listener_serves_console_health_and_real_forecast(self):
        status,html,headers=self.request('/console.html')
        self.assertEqual(status,200);self.assertIn(b'Krishna Defence System',html)
        self.assertIn(b'<script nonce=',html)
        self.assertIn("'nonce-",headers['Content-Security-Policy'])
        self.assertNotIn(b'r'*32,html);self.assertNotIn(b'o'*32,html)
        health=json.loads(self.request('/health')[1]);self.assertTrue(health['single_port'])
        status,raw,_=self.request('/bridge/replay?scenario=standard')
        self.assertEqual(status,200);self.assertEqual(len(json.loads(raw)['forecast']['trajectory']),4)

    def test_origin_and_arbitrary_operator_proxy_are_rejected(self):
        self.assertEqual(self.request('/bridge/status',headers={'Origin':'http://attacker.invalid'})[0],403)
        self.assertEqual(self.request('/bridge/status',headers={'Sec-Fetch-Site':'cross-site'})[0],403)
        self.assertEqual(self.request('/bridge/policy/create',{'target':'10.0.0.1'})[0],404)
        self.assertEqual(self.request('/api/status')[0],401)

    def test_known_and_unknown_lab_routes_remain_distinct(self):
        for scenario,route,status in [('syn_flood','arjuna',403),('dns_tunnel','krishna',200)]:
            code,raw,_=self.request('/bridge/simulate',{'scenario':scenario})
            self.assertEqual(code,200)
            d=json.loads(raw);self.assertEqual(d['forecast']['defence_signal']['route'],route)
            code,raw,_=self.request('/bridge/lab/probe',{'ticket':d['lab']['ticket']})
            self.assertEqual(code,status)

    def test_reference_assets_served_obsolete_surface_unavailable(self):
        for p in ('/reference.css','/reference-live.js','/console-v132-extra.js'):
            self.assertEqual(self.request(p)[0],200)
        self.assertEqual(self.request('/platform.html')[0],404)


if __name__ == '__main__':unittest.main()
