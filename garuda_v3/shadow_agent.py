"""On-premise closed-capture shadow collector. Never executes payloads or publishes policies.
A sensor atomically renames a completed capture to NAME.pcap.ready / NAME.csv.ready.
Inference runs locally; only result metadata and scores are retained in SQLite.
"""
import argparse,hashlib,json,sqlite3,time
from pathlib import Path
from .inference import ForecastService
from .data import convert,SCHEMA
from .pcap import convert_pcap

class ShadowAgent:
 def __init__(self,artifacts,database,retention_days=30):
  if not 1<=retention_days<=365:raise ValueError('Retention must be 1..365 days')
  self.service=ForecastService(artifacts);self.days=retention_days
  self.db=sqlite3.connect(database);self.db.execute('PRAGMA journal_mode=WAL')
  self.db.execute('CREATE TABLE IF NOT EXISTS observations (capture_sha256 TEXT, model_sha256 TEXT, created REAL, status TEXT, result TEXT, PRIMARY KEY(capture_sha256,model_sha256))')
  self.db.execute('CREATE INDEX IF NOT EXISTS observations_created ON observations(created)');self.db.commit()
 def process(self,path):
  path=Path(path)
  if path.is_symlink() or not path.is_file() or not path.name.endswith(('.pcap.ready','.csv.ready')):raise ValueError('Completed regular capture required')
  stat=path.stat()
  if not 0<stat.st_size<=256*1024**2:raise ValueError('Capture must be <=256 MiB')
  with path.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
  old=self.db.execute('SELECT result FROM observations WHERE capture_sha256=? AND model_sha256=?',(digest,self.service.model_hash)).fetchone()
  if old:return {'status':'already_processed','capture_sha256':digest}
  meta=self.service.meta;convert_fn=convert_pcap if path.name.endswith('.pcap.ready') else convert
  result=dict(capture_sha256=digest,model_sha256=self.service.model_hash,mode='shadow',automatic_containment=False,host_attribution='Capture endpoints only; global forecast is not attributed to an attacker IP')
  try:
   d=convert_fn(path,mode=meta['mode'],window_seconds=meta['window_seconds'],max_nodes=meta['max_nodes'])
   h=meta['history'];n=len(d['times'])
   if n<h:raise ValueError('Not enough complete windows')
   import numpy as np
   if np.any(np.diff(d['times'][-h:])!=meta['window_seconds']):raise ValueError('Noncontiguous recent windows')
   # Ready files must remain immutable through parsing.
   after=path.stat()
   if (stat.st_size,stat.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Capture changed during processing')
   payload=dict(schema=SCHEMA,mode=meta['mode'],window_seconds=meta['window_seconds'],x=d['x'][-h:].tolist(),adj=d['adj'][-h:].tolist(),mask=d['mask'][-h:].tolist(),times=d['times'][-h:].tolist(),node_names=d['metadata']['node_names'][-1],data_source='on_premise_completed_capture')
   f=self.service.predict(payload,explain=False)
   result.update(status='forecast',score=max(t['malicious_flow_probability'] for t in f['trajectory'])*100,trajectory=f['trajectory'],cutoff_epoch_seconds=f['cutoff_epoch_seconds'],alert=f['alert'],model_release_status='research_only',scope='Last contiguous history in completed capture; not continuous packet interception')
  except (ValueError,KeyError,TypeError) as e:result.update(status='withheld',reason=str(e))
  with self.db:
   self.db.execute('DELETE FROM observations WHERE created < ?',(time.time()-self.days*86400,))
   self.db.execute('INSERT OR IGNORE INTO observations VALUES (?,?,?,?,?)',(digest,self.service.model_hash,time.time(),result['status'],json.dumps(result,allow_nan=False)))
  return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True);p.add_argument('--inbox',required=True);p.add_argument('--database',required=True);p.add_argument('--once',action='store_true');p.add_argument('--interval',type=int,default=10);a=p.parse_args()
 if a.interval<2:p.error('Polling interval must be at least 2 seconds')
 inbox=Path(a.inbox)
 if not inbox.is_dir():p.error('Inbox must exist')
 agent=ShadowAgent(a.artifacts,a.database)
 try:
  while True:
   for path in sorted(inbox.glob('*.ready')):
    try:print(json.dumps(agent.process(path),allow_nan=False),flush=True)
    except (ValueError,OSError) as e:print(json.dumps({'status':'collector_error','reason':str(e)}),flush=True)
   if a.once:break
   time.sleep(a.interval)
 finally:agent.db.close()
if __name__=='__main__':main()
