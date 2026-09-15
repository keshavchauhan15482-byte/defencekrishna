import tempfile, shutil, pathlib, subprocess, os, time, urllib.request, urllib.error, threading, http.server
root=pathlib.Path(__file__).resolve().parents[1]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'UPSTREAM_ONLY')
    def log_message(self, *args): pass
backend=http.server.HTTPServer(('127.0.0.1',0), Handler)
threading.Thread(target=backend.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory() as folder:
    for p in root.iterdir():
        if p.suffix in ('.js','.json','.html'):
            shutil.copy(p, folder)
    env=dict(os.environ, GARUDA_OPERATOR_TOKEN='local-regression-operator-token-1234567890', PORT='18080', TARGET_URL=f'http://127.0.0.1:{backend.server_port}')
    with open('/tmp/krishna-proxy-test.log','w') as log:
        proc=subprocess.Popen(['node','proxy.js'], cwd=folder,env=env, stdout=log,stderr=log)
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18080/__sentinel/stats', headers={'Authorization':'Bearer local-regression-operator-token-1234567890'}),timeout=.2); break
                except Exception: time.sleep(.1)
            for path in ['/proxy.js','/counter-memory.json','/trained_world_model_weights.json','/package.json']:
                with urllib.request.urlopen('http://127.0.0.1:18080'+path,timeout=5) as r:
                    assert r.read()==b'UPSTREAM_ONLY', path
                print('PASS source not served:',path)
            with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18080/__sentinel/garuda-ai/forecast', headers={'Authorization':'Bearer local-regression-operator-token-1234567890'}),timeout=5) as r:
                import json
                result=json.load(r)
                assert result['data_source']=='synthetic_demo' and result['validated'] is False
                print('PASS demo provenance explicit')
        finally:
            proc.terminate(); proc.wait(timeout=5)
backend.shutdown()
