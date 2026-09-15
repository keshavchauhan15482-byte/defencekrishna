"""Actual loopback HTTP enforcement through the shipped proxy, with upstream receipts.
No external targets, executable exploits, or synthetic ML success labels.
"""
import hashlib,hmac,http.client,http.server,json,os,secrets,shutil,socket,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
receipts=[];checks=[]
class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        receipts.append(dict(path=self.path,time=time.time()))
        self.send_response(200);self.end_headers();self.wfile.write(b'UPSTREAM_RECEIPT')
    def log_message(self,*args):pass

def main():
    backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='garuda-http-') as temp:
        for p in ROOT.iterdir():
            if p.suffix in ('.js','.json','.html'):shutil.copy2(p,temp)
        key=secrets.token_hex(32);token=secrets.token_hex(32);file=Path(temp)/'policy.json'
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        issued=time.time()
        def publish(policies,t=None,bad=False):
            nonlocal issued
            issued=max(issued+.001,time.time()) if t is None else t
            payload=json.dumps(dict(version=1,issued_at=issued,policies=policies),separators=(',',':'))
            envelope=dict(payload=payload,signature='00' if bad else hmac.new(key.encode(),payload.encode(),hashlib.sha256).hexdigest())
            tmp=file.with_suffix('.tmp');tmp.write_text(json.dumps(envelope));tmp.replace(file);time.sleep(.3)
        publish([])
        env={k:v for k,v in os.environ.items() if not k.startswith(('GARUDA_','TRUSTED_PROXY'))}
        env.update(PORT=str(port),BIND_HOST='127.0.0.1',TARGET_URL=f'http://127.0.0.1:{backend.server_port}',GARUDA_OPERATOR_TOKEN=token,GARUDA_POLICY_FILE=str(file),GARUDA_POLICY_KEY=key)
        log=ROOT/'datasets/v11/proxy_lab.log'
        with log.open('w') as output:
            proc=subprocess.Popen(['node','proxy.js'],cwd=temp,env=env,stdout=output,stderr=output)
            def request(path='/',ip='127.0.0.2',headers=None,method='GET'):
                c=http.client.HTTPConnection('127.0.0.1',port,timeout=5,source_address=(ip,0))
                try:c.request(method,path,headers=headers or {});r=c.getresponse();return r.status,r.read()
                finally:c.close()
            def check(name,path,status,ip='127.0.0.2',headers=None,method='GET',forwarded=False):
                before=len(receipts);code,body=request(path,ip,headers,method)
                assert code==status,(name,code,body[:300])
                assert len(receipts)-before==int(forwarded),(name,'upstream receipt count',len(receipts)-before)
                checks.append(dict(name=name,status=code,upstream_receipts=len(receipts)-before,passed=True))
            try:
                for _ in range(100):
                    try:request('/__sentinel/stats','127.0.0.1',{'Authorization':'Bearer '+token});break
                    except (OSError,http.client.HTTPException):
                        if proc.poll() is not None:raise RuntimeError('Proxy exited; inspect proxy_lab.log')
                        time.sleep(.1)
                check('Legitimate request reaches protected app','/baseline',200,forwarded=True)
                check('Unauthenticated management denied','/__sentinel/stats',401,ip='127.0.0.1')
                check('Fabricated prediction mitigation retired','/__sentinel/garuda-ai/mitigate',410,ip='127.0.0.1',headers={'Authorization':'Bearer '+token},method='POST')
                publish([dict(id='lab-reviewed-policy',target='127.0.0.2',expires=time.time()+30,status='active')])
                verified_time=issued
                check('Signed scoped policy prevents upstream delivery','/protected',403)
                check('Unrelated client stays available','/other-client',200,ip='127.0.0.3',forwarded=True)
                check('Forwarded header cannot evade scoped policy','/spoof',403,headers={'X-Forwarded-For':'127.0.0.3'})
                publish([],bad=True)
                check('Invalid signature does not lift containment','/tamper',403)
                publish([],t=verified_time-1)
                check('Stale signed revoke rejected','/replay',403)
                publish([])
                check('Emergency signed revoke restores delivery','/recovered',200,forwarded=True)
                publish([dict(id='expiry-test',target='127.0.0.2',expires=time.time()+1,status='active')])
                check('Short TTL policy initially blocks','/ttl-active',403)
                time.sleep(1)
                check('Expired policy no longer blocks','/ttl-expired',200,forwarded=True)
                check('Known SQL injection is denied by detection engine',"/login?q=%27%20OR%201%3D1--",403,ip='127.0.0.4')
            finally:proc.terminate();proc.wait(timeout=5)
    backend.shutdown();backend.server_close()
    result=dict(checks=checks,passed=len(checks),upstream_receipts=receipts,
        scope='Loopback HTTP proxy enforcement; operator-signed policies and known-payload detection',
        garuda_forecast_trigger_tested=False,unknown_attack_generalisation_tested=False,
        production_effectiveness_proven=False)
    (ROOT/'datasets/v11/http_lab_results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))

if __name__=='__main__':main()
