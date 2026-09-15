"""Bounded local-only WAF probes. Inert upstream records arrivals; executes no payloads."""
import http.server,json,os,shutil,socket,subprocess,tempfile,threading,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from urllib.parse import quote
import numpy as np
from garuda_v3.security import PolicyStore
from garuda_v3.inference import ForecastService
from garuda_v3.data import load_dataset,SCHEMA
ROOT=Path(__file__).resolve().parents[1]
ARRIVALS=[]
class Backend(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.reply()
 def do_POST(self):self.reply()
 def reply(self):
  body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  ARRIVALS.append(self.headers.get('X-Lab-Case'))
  status=401 if self.path=='/api/login' else 200
  self.send_response(status);self.end_headers();self.wfile.write(b'INERT_LAB_UPSTREAM')
 def log_message(self,*args):pass

def main():
 backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),Backend)
 thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
 result={'scope':'Local loopback proxy and inert upstream only; payload probes are not successful exploitation tests',
  'isolation':'Temporary copy of shipped JS/JSON; unique simulated client IP per payload. Trusted-forwarder topology is explicit. Online signature learning can affect later cases.',
  'cases':[]}
 with tempfile.TemporaryDirectory() as tmp:
  for p in ROOT.iterdir():
   if p.suffix in ('.js','.json','.html'):shutil.copy2(p,tmp)
  if os.environ.get('GARUDA_LAB_CLEAN_MEMORY')=='1':
   for memory in Path(tmp).glob('counter-memory*.json'):memory.unlink()
   result['memory_profile']='fresh counter memory in temporary copy'
  else:result['memory_profile']='as shipped'
  store=PolicyStore(Path(tmp)/'runtime',key='k'*40,allowed_cidrs=['198.51.100.0/24'],enforce=True)
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  env=dict(os.environ,PORT=str(port),BIND_HOST='127.0.0.1',TARGET_URL=f'http://127.0.0.1:{backend.server_port}',GARUDA_POLICY_FILE=str(Path(tmp)/'runtime/policy.json'),GARUDA_POLICY_KEY='k'*40,GARUDA_OPERATOR_TOKEN='o'*40,TRUSTED_PROXY_IPS='127.0.0.1,::ffff:127.0.0.1')
  log=open(Path(tmp)/'proxy.log','wb');proc=subprocess.Popen(['node','proxy.js'],cwd=tmp,env=env,stdout=log,stderr=log)
  def request(name,path='/',body=None,ctype='application/json',ip='198.51.100.250',token=None):
   headers={'X-Lab-Case':name,'X-Forwarded-For':ip,'Content-Type':ctype,'User-Agent':'Garuda-local-validation/1.0'}
   if token:headers['Authorization']='Bearer '+token
   req=Request(f'http://127.0.0.1:{port}'+path,data=body,headers=headers)
   start=time.monotonic()
   try:
    with urlopen(req,timeout=5) as r:status=r.status;raw=r.read(65536)
   except HTTPError as e:status=e.code;raw=e.read(65536)
   try:detail=json.loads(raw)
   except ValueError:detail={}
   return dict(name=name,status=status,reached_upstream=name in ARRIVALS,latency_ms=round((time.monotonic()-start)*1000,2),
    reason=detail.get('reason',detail.get('error')),details=detail.get('details'),policy_id=detail.get('policy_id'))
  try:
   for _ in range(60):
    try:request('startup');break
    except OSError:time.sleep(.05)
   benign=[('home','/',None,'application/json'),('ordinary_search','/search?q=network+security',None,'application/json'),
    ('apostrophe_name','/search?q='+quote("O'Reilly"),None,'application/json'),('union_word','/search?q=student+union',None,'application/json'),
    ('json_note','/api/note',json.dumps({'note':'Please select a blue shirt'}).encode(),'application/json')]
   attacks=[('sqli_query','/items?id='+quote("1' OR '1'='1'--"),None,'application/json'),
    ('sqli_union','/items?id='+quote('1 UNION SELECT username,password FROM users--'),None,'application/json'),
    ('xss_script','/search?q='+quote('<script>alert(1)</script>'),None,'application/json'),
    ('xss_svg','/search?q='+quote('<svg/onload=alert(1)>'),None,'application/json'),
    ('path_traversal','/download?file='+quote('../../../../etc/passwd',safe=''),None,'application/json'),
    ('command_injection','/lookup?host='+quote('example.invalid; id'),None,'application/json'),
    ('template_expression','/render?name='+quote('{{7*7}}'),None,'application/json'),
    ('nosql_json','/api/find',b'{"username":{"$ne":null},"password":{"$ne":null}}','application/json'),
    ('sqli_form','/api/search',b'q=1%27+OR+1%3D1--','application/x-www-form-urlencoded'),
    ('xxe_xml','/api/import',b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///garuda-lab-marker">]><x>&e;</x>','application/xml'),
    ('ssrf_parameter','/fetch?url='+quote('http://127.0.0.1:1/garuda-lab'),None,'application/json'),
    ('sqli_double_encoded','/items?id='+quote(quote("1' OR 1=1--",safe=''),safe=''),None,'application/json')]
   for i,(name,path,body,ctype) in enumerate(benign+attacks,1):
    row=request(name,path,body,ctype,ip=f'198.51.100.{i}');row['kind']='benign' if i<=len(benign) else 'attack_probe';result['cases'].append(row)
   result['management']=[request('unauth_stats','/__sentinel/stats'),request('retired_predictive_lockdown','/__sentinel/predictive-lockdown',token='o'*40)]
   result['login_sequence']=[request('login_'+str(i),'/api/login',b'{"username":"lab_user","password":"wrong"}',ip='198.51.100.200') for i in range(1,13)]
   # Deliberately choose a high-risk recorded snapshot for wiring inspection, not accuracy measurement.
   folder=ROOT/'garuda_v3/artifacts/residual_run';service=ForecastService(folder)
   with np.load(folder/'gnn_lstm_test_predictions.npz',allow_pickle=False) as saved:
    idx=int(np.argmax(saved['probabilities'].max(1)));source,start=map(int,saved['example_indices'][idx])
   d=load_dataset(ROOT/'garuda_v3/artifacts'/(['Thursday.npz','Friday.npz'][source]));stop=start+service.meta['history']
   payload=dict(schema=SCHEMA,mode='service',window_seconds=10,x=d['x'][start:stop].tolist(),adj=d['adj'][start:stop].tolist(),mask=d['mask'][start:stop].tolist(),times=d['times'][start:stop].tolist(),node_names=d['metadata']['node_names'][stop-1])
   before=request('before_prediction');forecast=service.predict(payload);after=request('after_prediction')
   policy=store.propose('198.51.100.250',30,'operator controlled local enforcement test');time.sleep(.35)
   blocked=request('operator_policy_active');store.revoke(policy['id']);time.sleep(.35);revoked=request('operator_policy_revoked')
   result['forecast_to_enforcement']=dict(snapshot_selection='highest-risk stored held-out service snapshot; integration probe only',
    peak_probability=max(t['malicious_flow_probability'] for t in forecast['trajectory']),alert=forecast['alert'],automatic_containment=forecast['automatic_containment'],
    before=before,after_prediction=after,after_operator_policy=blocked,after_revocation=revoked,
    attribution_limit='The service graph does not identify the simulated client IP; operator policy uses a deliberately chosen lab IP. This is not autonomous model-to-IP containment.')
   result['summary']=dict(attack_probes=len(attacks),attack_probes_not_forwarded=sum(not r['reached_upstream'] for r in result['cases'] if r['kind']=='attack_probe'),
    benign_probes=len(benign),benign_probes_not_forwarded=sum(not r['reached_upstream'] for r in result['cases'] if r['kind']=='benign'),
    forecast_triggered_automatic_block=not after['reached_upstream'],operator_rule_enforced=blocked['status']==403 and not blocked['reached_upstream'],revocation_restores=revoked['status']==200 and revoked['reached_upstream'])
  finally:
   proc.terminate();proc.wait(timeout=5);log.close();store.close()
 backend.shutdown();backend.server_close()
 out=ROOT/'security_validation'/('clean_memory_results.json' if os.environ.get('GARUDA_LAB_CLEAN_MEMORY')=='1' else 'local_attack_results.json');out.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
