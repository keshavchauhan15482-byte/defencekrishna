import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from garuda_v3.security import PolicyStore
from garuda_v3.server import App

class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'UPSTREAM')
    def log_message(self,*args):pass
class ProxyPolicyTests(unittest.TestCase):
    def test_signed_policy_blocks_then_revoke_restores_traffic(self):
        root=Path(__file__).resolve().parents[2]
        backend=http.server.HTTPServer(('127.0.0.1',0),Upstream);threading.Thread(target=backend.serve_forever,daemon=True).start()
        with tempfile.TemporaryDirectory() as folder:
            for p in root.iterdir():
                if p.suffix in ('.js','.json','.html'):shutil.copy(p,folder)
            store=PolicyStore(Path(folder)/'runtime',key='k'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True)
            with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            env=dict(os.environ,PORT=str(port),TARGET_URL=f'http://127.0.0.1:{backend.server_port}',GARUDA_POLICY_FILE=str(Path(folder)/'runtime/policy.json'),GARUDA_POLICY_KEY='k'*40,GARUDA_OPERATOR_TOKEN='o'*40,TRUSTED_PROXY_IPS='127.0.0.1,::ffff:127.0.0.1')
            proc=subprocess.Popen(['node','proxy.js'],cwd=folder,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            def request(path='/',token=None,ip='198.51.100.2'):
                headers={'X-Forwarded-For':ip}
                if token:headers['Authorization']='Bearer '+token
                try:
                    with urlopen(Request(f'http://127.0.0.1:{port}'+path,headers=headers),timeout=3) as r:return r.status,r.read()
                except HTTPError as e:return e.code,e.read()
            try:
                for _ in range(40):
                    try:request();break
                    except OSError:time.sleep(.05)
                self.assertEqual(request()[0],200)
                self.assertEqual(request('/__sentinel/stats')[0],401)
                self.assertEqual(request('/__sentinel/stats',token='o'*40)[0],200)
                # Real trained forecast triggers containment for the operator-bound lab IP.
                app=App(root/'garuda_v3/artifacts/residual_run',Path(folder)/'runtime','v'*40,'o'*40,
                        policy_key='k'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True,lab_automation=True)
                try:
                    app.response.arm('198.51.100.2')
                    forecast=app.forecast(json.loads((root/'garuda_v3/artifacts/residual_run/alert_replay.json').read_text()))
                    self.assertTrue(forecast['automatic_containment'])
                    policy=forecast['defence_signal']['policy']
                finally:app.policy.close()
                time.sleep(.3)
                status,body=request();self.assertEqual(status,403);self.assertEqual(json.loads(body)['policy_id'],policy['id'])
                self.assertEqual(request(ip='198.51.100.3')[0],200)
                store.revoke(policy['id']);time.sleep(.3);self.assertEqual(request()[0],200)
                # A forged control-plane file never becomes an active block.
                envelope=json.loads((Path(folder)/'runtime/policy.json').read_text());envelope['signature']='0'*64
                (Path(folder)/'runtime/policy.json').write_text(json.dumps(envelope));time.sleep(.3)
                self.assertEqual(request()[0],200)
            finally:proc.terminate();proc.wait(timeout=5);store.close()
        backend.shutdown();backend.server_close()
if __name__=='__main__':unittest.main()
