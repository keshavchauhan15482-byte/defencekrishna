"""Garuda signals, reviewed Arjuna memory, Krishna triage and signed Sudarshana policies.
Automation is limited to an explicitly armed lab IP; graph risk never invents IP attribution.
"""
import hashlib,ipaddress,json,time,uuid

LAB_NETS=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')]
class ResponseCoordinator:
    def __init__(self,policy,lab_enabled=False):
        self.policy=policy;self.lab_enabled=lab_enabled;self.arm_state=None
        with policy.lock:
            policy.db.execute('CREATE TABLE IF NOT EXISTS response_events (id TEXT PRIMARY KEY, created REAL, payload TEXT)')
            policy.db.execute('CREATE TABLE IF NOT EXISTS threat_memory (fingerprint TEXT PRIMARY KEY, attack_type TEXT, evidence TEXT, approved REAL)')
            policy.db.commit()
    def status(self):
        with self.policy.lock:
            if self.arm_state and self.arm_state['expires']<=time.time():self.arm_state=None
            events=[json.loads(row[0]) for row in self.policy.db.execute('SELECT payload FROM response_events ORDER BY created DESC LIMIT 40')]
            memory=[dict(fingerprint=f,attack_type=a,evidence=e,approved=t) for f,a,e,t in self.policy.db.execute('SELECT * FROM threat_memory ORDER BY approved DESC LIMIT 40')]
            return dict(lab_enabled=self.lab_enabled,armed=self.arm_state,events=events,memory=memory,
                scope='Application-proxy containment; signing authenticates policies, not data encryption or a breach-prevention guarantee')
    def arm(self,target,ttl=30,duration=120):
        ip=ipaddress.ip_address(target)
        if not self.lab_enabled or not self.policy.enforce:raise ValueError('Lab automation and signed enforcement must be enabled at startup')
        if len(self.policy.key)<32:raise ValueError('Signing key required')
        if not any(ip in n for n in LAB_NETS) or not any(ip in n for n in self.policy.allowed):raise ValueError('Lab target outside explicit scope')
        if isinstance(ttl,bool) or not isinstance(ttl,int) or not 10<=ttl<=60:raise ValueError('Lab policy TTL must be 10..60 seconds')
        if isinstance(duration,bool) or not isinstance(duration,int) or not 30<=duration<=300:raise ValueError('Arm duration must be 30..300 seconds')
        with self.policy.lock:
            self.arm_state=dict(target=str(ip),ttl=ttl,expires=time.time()+duration,binding='operator-selected lab replay target; not inferred attacker attribution')
            self.policy.event('arm_lab_response',self.arm_state);self.policy.db.commit()
            return self.arm_state
    def disarm(self):
        with self.policy.lock:
            self.arm_state=None;self.policy.event('disarm_response',{});self.policy.db.commit()
        return dict(status='disarmed',existing_policies='retain TTL unless revoked or emergency stop used')
    def _save(self,event):
        self.policy.db.execute('INSERT OR REPLACE INTO response_events VALUES (?,?,?)',(event['id'],event['created'],json.dumps(event,allow_nan=False)))
        self.policy.db.commit()
    def _contain(self,event):
        self.status()
        if not self.arm_state:
            event['sudarshana']='awaiting_authorization';return
        target=self.arm_state['target'];active=next((p for p in self.policy.active() if p['target']==target),None)
        if active:policy=dict(id=active['id'],status='active',enforcement='existing_policy')
        else:policy=self.policy.propose(target,self.arm_state['ttl'],f"Garuda lab signal {event['id'][:8]} / {event['route']}")
        event.update(target=target,target_binding=self.arm_state['binding'],policy=policy,sudarshana='signed_policy_published',
                     enforcement_confirmation='pending_proxy_observation')
    def observe(self,forecast,graph):
        fingerprint=hashlib.sha256(json.dumps({k:graph[k] for k in ('x','adj','mask','times')},sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        with self.policy.lock:
            match=self.policy.db.execute('SELECT attack_type FROM threat_memory WHERE fingerprint=?',(fingerprint,)).fetchone()
            alert=bool(forecast['alert']);route='arjuna' if match else 'krishna' if alert else 'garuda'
            event=dict(id=str(uuid.uuid4()),created=time.time(),fingerprint=fingerprint,route=route,
                classification='reviewed_snapshot_match' if match else 'unreviewed_forecast' if alert else 'below_alert_threshold',
                attack_type=match[0] if match else None,risk=max(t['malicious_flow_probability'] for t in forecast['trajectory']),
                forecast_alert=alert,source=forecast.get('data_source'),model_sha256=forecast['model_sha256'],
                review_status='approved_match' if match else 'pending' if alert else 'not_requested',
                features=forecast.get('explanation',{}).get('feature_attributions',[])[:5],sudarshana='standby')
            if alert or match:self._contain(event)
            self.policy.event('defence_signal',dict(id=event['id'],route=route,fingerprint=fingerprint,sudarshana=event['sudarshana']))
            self._save(event)
            return event
    def approve(self,event_id,attack_type,evidence):
        if not isinstance(attack_type,str) or not 3<=len(attack_type)<=80:raise ValueError('Attack type required')
        if not isinstance(evidence,str) or not 12<=len(evidence)<=500:raise ValueError('Review evidence required')
        with self.policy.lock:
            row=self.policy.db.execute('SELECT payload FROM response_events WHERE id=?',(event_id,)).fetchone()
            if not row:raise ValueError('Unknown response event')
            event=json.loads(row[0])
            if not event['forecast_alert']:raise ValueError('Only alert candidates can be approved')
            self.policy.db.execute('INSERT OR REPLACE INTO threat_memory VALUES (?,?,?,?)',(event['fingerprint'],attack_type,evidence,time.time()))
            event.update(review_status='approved',attack_type=attack_type)
            self.policy.event('review_snapshot_fingerprint',dict(event_id=event_id,attack_type=attack_type,evidence=evidence));self._save(event)
            return dict(status='approved',scope='Exact reviewed snapshot fingerprint; no generic exploit signature or software patch generated')
    def escalate(self,event_id,evidence):
        if not isinstance(evidence,str) or not 12<=len(evidence)<=500:raise ValueError('Incident evidence required')
        with self.policy.lock:
            row=self.policy.db.execute('SELECT payload FROM response_events WHERE id=?',(event_id,)).fetchone()
            if not row:raise ValueError('Unknown response event')
            event=json.loads(row[0]);event.update(route='sudarshana',incident_status='operator_reported_breach',incident_evidence=evidence)
            self._contain(event);self.policy.event('operator_incident_escalation',dict(event_id=event_id,evidence=evidence));self._save(event)
            return event
