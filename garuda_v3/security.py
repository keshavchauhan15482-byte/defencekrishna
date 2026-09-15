"""Single-instance operator-approved, expiring proxy policy and auditable changes."""
import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

class PolicyStore:
    def __init__(self,folder,key='',allowed_cidrs=(),enforce=False):
        self.folder=Path(folder);self.folder.mkdir(parents=True,exist_ok=True)
        self.key=key;self.enforce=enforce;self.allowed=[ipaddress.ip_network(x) for x in allowed_cidrs]
        self.lock=threading.RLock()
        self.db=sqlite3.connect(self.folder/'audit.sqlite',check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT, previous_hash TEXT, hash TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, target TEXT, expires REAL, reason TEXT, status TEXT)')
        self.db.commit()
        os.chmod(self.folder/'audit.sqlite',0o600)
        if not self.verify():raise ValueError('Audit integrity failure; restore and investigate')
        self.publish()
    def verify(self):
        with self.lock:
            previous='0'*64
            for payload,prev,digest in self.db.execute('SELECT payload,previous_hash,hash FROM events ORDER BY id'):
                if prev!=previous or hashlib.sha256((prev+payload).encode()).hexdigest()!=digest:return False
                previous=digest
            return True
    def event(self,action,details):
        payload=json.dumps(dict(time=time.time(),action=action,details=details),sort_keys=True,separators=(',',':'))
        previous=self.db.execute('SELECT hash FROM events ORDER BY id DESC LIMIT 1').fetchone()
        previous=previous[0] if previous else '0'*64
        digest=hashlib.sha256((previous+payload).encode()).hexdigest()
        self.db.execute('INSERT INTO events(payload,previous_hash,hash) VALUES(?,?,?)',(payload,previous,digest))
    def active(self):
        with self.lock:
            return [dict(id=i,target=t,expires=e,reason=r,status=s) for i,t,e,r,s in self.db.execute('SELECT * FROM policies WHERE status="active" AND expires>?',(time.time(),))]
    def publish(self):
        with self.lock:
            now=time.time()
            self.db.execute('UPDATE policies SET status="expired" WHERE status="active" AND expires<=?',(now,));self.db.commit()
            policies=self.active() if self.enforce else []
            payload=json.dumps(dict(version=1,issued_at=now,policies=policies),sort_keys=True,separators=(',',':'))
            envelope=dict(payload=payload,signature=hmac.new(self.key.encode(),payload.encode(),hashlib.sha256).hexdigest())
            temp=self.folder/'policy.tmp';temp.write_text(json.dumps(envelope));os.chmod(temp,0o600);os.replace(temp,self.folder/'policy.json')
    def propose(self,target,ttl,reason):
        address=ipaddress.ip_address(target)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError('Critical/reserved address is protected')
        if not any(address in network for network in self.allowed):raise ValueError('Target is outside configured containment scope')
        if not isinstance(ttl,int) or isinstance(ttl,bool) or not 10<=ttl<=900:raise ValueError('TTL must be 10..900 seconds')
        if not isinstance(reason,str) or not 8<=len(reason)<=240:raise ValueError('Provide an 8..240 character reason')
        with self.lock:
            if len(self.active())>=100:raise ValueError('Active policy limit reached')
            if self.enforce and len(self.key)<32:raise ValueError('Enforcement signing key not configured')
            i=str(uuid.uuid4());status='active' if self.enforce else 'dry_run'
            self.db.execute('INSERT INTO policies VALUES(?,?,?,?,?)',(i,str(address),time.time()+ttl,reason,status))
            self.event('operator_containment',dict(id=i,target=str(address),ttl=ttl,status=status));self.db.commit();self.publish()
            return dict(id=i,status=status,enforcement='signed_proxy_policy_published_confirmation_required' if self.enforce else 'dry_run_no_traffic_blocked')
    def revoke(self,i):
        with self.lock:
            row=self.db.execute('SELECT id FROM policies WHERE id=?',(i,)).fetchone()
            if not row:raise ValueError('Unknown policy')
            self.db.execute('UPDATE policies SET status="revoked" WHERE id=?',(i,));self.event('operator_revoke',dict(id=i));self.db.commit();self.publish()
            return dict(id=i,status='revoked')
    def kill_switch(self):
        with self.lock:
            self.db.execute('UPDATE policies SET status="revoked" WHERE status="active"');self.event('operator_kill_switch',{});self.db.commit();self.publish()
            return {'status':'all_v3_policies_revoked'}
    def close(self):self.db.close()
