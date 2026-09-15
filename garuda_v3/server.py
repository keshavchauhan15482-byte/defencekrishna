"""Authenticated, offline single-instance demo service (stdlib + NumPy).
Production deployments still require a TLS gateway, operational monitoring and external review.
"""
import argparse
import collections
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
from .data import convert,SCHEMA
from .pcap import convert_pcap
from .inference import ForecastService
from .security import PolicyStore
from .response import ResponseCoordinator
from .benchmark_summary import summarize

MAX_BODY=72*1024*1024
class App:
    def __init__(self,artifacts,runtime,reader_token,operator_token,policy_key='',allowed_cidrs=(),enforce=False,lab_automation=False):
        if min(len(reader_token),len(operator_token))<32 or reader_token==operator_token:raise ValueError('Distinct tokens of at least 32 characters required')
        self.reader=reader_token;self.operator=operator_token;self.service=ForecastService(artifacts)
        self.policy=PolicyStore(runtime,policy_key,allowed_cidrs,enforce)
        self.response=ResponseCoordinator(self.policy,lab_automation)
        self.compute=threading.BoundedSemaphore(1);self.rates=collections.defaultdict(collections.deque);self.rate_lock=threading.Lock()
    def role(self,token):
        if hmac.compare_digest(token,self.operator):return 'operator'
        if hmac.compare_digest(token,self.reader):return 'viewer'
        return None
    def rate_ok(self,role):
        with self.rate_lock:
            q=self.rates[role];now=time.monotonic()
            while q and q[0]<now-60:q.popleft()
            if len(q)>=60:return False
            q.append(now);return True
    def forecast(self,payload):
        forecast=self.service.predict(payload)
        forecast['defence_signal']=self.response.observe(forecast,payload)
        forecast['automatic_containment']=forecast['defence_signal'].get('policy',{}).get('status')=='active'
        forecast['containment_scope']='armed_lab_only; publication requires proxy confirmation'
        return forecast
    def analyze(self,content,kind,mode):
        suffix='.csv' if kind=='csv' else '.pcap'
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/('capture'+suffix);path.write_bytes(content)
            settings=dict(window_seconds=self.service.meta['window_seconds'],max_nodes=self.service.meta['max_nodes'])
            d=convert(path,mode,**settings) if kind=='csv' else convert_pcap(path,mode,**settings)
        history=self.service.meta['history']
        if len(d['times'])<history:raise ValueError('Insufficient observed history')
        # Last completed contiguous history only; never pad missing traffic.
        payload=dict(schema=SCHEMA,mode=mode,window_seconds=d['metadata']['window_seconds'],
            x=d['x'][-history:].tolist(),adj=d['adj'][-history:].tolist(),mask=d['mask'][-history:].tolist(),
            times=d['times'][-history:].tolist(),node_names=d['metadata']['node_names'][-1],data_source='uploaded_'+kind)
        metadata={k:v for k,v in d['metadata'].items() if k!='node_names'}
        try:forecast=self.forecast(payload)
        except ValueError as exc:return dict(graph=payload,ingestion=metadata,forecast=None,inference_unavailable_reason=str(exc))
        return dict(graph=payload,ingestion=metadata,forecast=forecast)

class Handler(BaseHTTPRequestHandler):
    server_version='Garuda/3'
    def setup(self):
        super().setup();self.connection.settimeout(15)
    def log_message(self,format,*args):pass  # tokens/bodies never logged
    def respond(self,status,data,mime='application/json'):
        body=json.dumps(data,allow_nan=False).encode() if mime=='application/json' else data
        self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers();self.wfile.write(body)
    def do_OPTIONS(self):self.respond(405,{'error':'Cross-origin requests disabled'})
    def do_GET(self):self.handle_request()
    def do_POST(self):self.handle_request()
    def handle_request(self):
        app=self.server.app;url=urlsplit(self.path);method=self.command
        # Exact host/origin comparison protects local services against browser rebinding/CSRF.
        host=self.headers.get('Host','')
        if host not in self.server.allowed_hosts:return self.respond(403,{'error':'Unexpected host'})
        origin=self.headers.get('Origin')
        if origin and origin!='http://'+host:return self.respond(403,{'error':'Cross-origin request denied'})
        if method=='GET' and url.path in ('/','/app.js','/style.css'):
            name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[url.path]
            mime={'/':'text/html; charset=utf-8','/app.js':'application/javascript','/style.css':'text/css'}[url.path]
            return self.respond(200,(Path(__file__).parent/'ui'/name).read_bytes(),mime)
        if method=='GET' and url.path=='/health':return self.respond(200,{'status':'alive'})
        auth=self.headers.get('Authorization','');token=auth[7:] if auth.startswith('Bearer ') else ''
        role=app.role(token)
        if not role:return self.respond(401,{'error':'Bearer token required'})
        if not app.rate_ok(role):return self.respond(429,{'error':'Request quota reached; retry after one minute'})
        if method=='GET':
            if url.path=='/api/status':return self.respond(200,dict(role=role,model=app.service.meta,model_sha256=app.service.model_hash,policies=app.policy.active(),audit_integrity=app.policy.verify(),enforcement_enabled=app.policy.enforce))
            if url.path=='/api/response':return self.respond(200,app.response.status())
            if url.path=='/api/metrics':return self.respond(200,app.service.metrics)
            if url.path=='/api/benchmarks':return self.respond(200,summarize())
            if url.path=='/api/replay':
                if not app.compute.acquire(blocking=False):return self.respond(503,{'error':'Inference busy'})
                try:
                    scenario=parse_qs(url.query).get('scenario',['standard'])[0]
                    if scenario not in ('standard','alert','hosts'):return self.respond(422,{'error':'Unknown replay scenario'})
                    replay_path=app.service.folder/({'alert':'alert_replay.json','hosts':'host_replay.json','standard':'replay.json'}[scenario])
                    if not replay_path.exists():return self.respond(404,{'error':'Selected recorded replay unavailable for this checkpoint'})
                    payload=json.loads(replay_path.read_text())
                    try:result=dict(graph=payload,forecast=app.forecast(payload))
                    except ValueError as exc:result=dict(graph=payload,forecast=None,inference_unavailable_reason=str(exc))
                    return self.respond(200,result)
                finally:app.compute.release()
            return self.respond(404,{'error':'Unknown endpoint'})
        if (url.path.startswith('/api/policy/') or url.path.startswith('/api/response/')) and role!='operator':return self.respond(403,{'error':'Operator role required'})
        try:
            if self.headers.get('Transfer-Encoding'):raise ValueError('Chunked request bodies not supported')
            values=self.headers.get_all('Content-Length',[])
            if len(values)!=1:raise ValueError('One Content-Length required')
            length=int(values[0])
            if not 0<length<=MAX_BODY:return self.respond(413,{'error':'Upload must be 1 byte to 72 MiB'})
            if url.path!='/api/analyze' and length>2*1024*1024:return self.respond(413,{'error':'JSON request limit 2 MiB'})
            if not app.compute.acquire(blocking=False):return self.respond(503,{'error':'Inference busy'})
            try:
                content=self.rfile.read(length)
                if len(content)!=length:raise ValueError('Incomplete upload')
                if url.path=='/api/analyze':
                    query=parse_qs(url.query);kind=query.get('type',['csv'])[0];mode=query.get('mode',['service'])[0]
                    if kind not in ('csv','pcap') or mode not in ('service','host'):raise ValueError('Invalid capture type or graph mode')
                    result=app.analyze(content,kind,mode)
                else:
                    obj=json.loads(content)
                    if not isinstance(obj,dict):raise ValueError('JSON object required')
                    if url.path=='/api/forecast':result=app.forecast(obj)
                    elif url.path=='/api/response/arm':result=app.response.arm(obj['target'],obj.get('ttl',30),obj.get('duration',120))
                    elif url.path=='/api/response/disarm':result=app.response.disarm()
                    elif url.path=='/api/response/approve':result=app.response.approve(obj['id'],obj['attack_type'],obj['evidence'])
                    elif url.path=='/api/response/escalate':result=app.response.escalate(obj['id'],obj['evidence'])
                    elif url.path=='/api/policy/create':result=app.policy.propose(obj['target'],obj['ttl'],obj['reason'])
                    elif url.path=='/api/policy/revoke':result=app.policy.revoke(obj['id'])
                    elif url.path=='/api/policy/kill':
                        app.response.disarm();result=app.policy.kill_switch()
                    else:return self.respond(404,{'error':'Unknown endpoint'})
                return self.respond(200,result)
            finally:app.compute.release()
        except (ValueError,KeyError,TypeError,OverflowError,UnicodeError):return self.respond(422,{'error':'Invalid input or unsupported schema; inspect capture fields, graph dimensions and policy scope'})
        except TimeoutError:return self.respond(408,{'error':'Upload timed out'})
        except Exception:return self.respond(500,{'error':'Internal operation failed; no success assumed'})

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,app):
        super().__init__(address,Handler);self.app=app
        self.allowed_hosts={f'127.0.0.1:{self.server_port}',f'localhost:{self.server_port}'}
        self.slots=threading.BoundedSemaphore(16)
    def process_request(self,request,client_address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,client_address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--port',type=int,default=8090);p.add_argument('--artifacts',default='garuda_v3/artifacts/residual_run');p.add_argument('--runtime',default='garuda_v3/runtime');args=p.parse_args()
    runtime=Path(args.runtime);runtime.mkdir(parents=True,exist_ok=True);os.chmod(runtime,0o700)
    credentials=runtime/'access.json'
    if not credentials.exists():
        with os.fdopen(os.open(credentials,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
            json.dump(dict(viewer_token=secrets.token_urlsafe(32),operator_token=secrets.token_urlsafe(32)),f)
    access=json.loads(credentials.read_text())
    app=App(args.artifacts,runtime,os.environ.get('GARUDA_READ_TOKEN',access['viewer_token']),os.environ.get('GARUDA_OPERATOR_TOKEN',access['operator_token']),
            os.environ.get('GARUDA_POLICY_KEY',''),[c for c in os.environ.get('GARUDA_ALLOWED_CIDRS','').split(',') if c],os.environ.get('GARUDA_ENFORCE')=='1',os.environ.get('GARUDA_LAB_AUTOMATION')=='1')
    server=Server(('127.0.0.1',args.port),app)
    print(f'Garuda v3: http://127.0.0.1:{server.server_port} — local tokens: {credentials}. Dry-run by default.',flush=True)
    try:server.serve_forever()
    finally:server.server_close();app.policy.close()
if __name__=='__main__':main()
