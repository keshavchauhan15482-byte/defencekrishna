import assert from 'node:assert/strict';
import test from 'node:test';
import {
  handleKrishnaLiveRequest,
  sensorAuthorized,
  validateSensorPayload,
} from '../site_integration/chatgpt_sites/live_routes.mjs';

const token = 'sensor-' + 'Z'.repeat(40);
const HORIZONS = [10,20,30,40];

function sample() {
  return {
    schema:'krishna-live-v1', kind:'forecast',
    capture_sha256:'a'.repeat(64), model_sha256:'b'.repeat(64),
    cutoff_epoch_seconds:Date.now()/1000-1,
    trajectory:HORIZONS.map((n,i)=>({
      horizon_seconds:n,malicious_flow_probability:0.1+i/10,
    })),
    alert:true, supported:false, automatic_containment:false,
  };
}

class FakeDb {
  constructor() { this.rows=[]; this.sequence=0; }
  prepare(sql) {
    const db=this;
    return {
      args:[],
      bind(...args) {this.args=args;return this;},
      async first() {
        if(sql.includes('COUNT(*)'))return {n:db.rows.filter(x=>x.received_at>this.args[0]).length};
        if(sql.includes('capture_sha256 = ?'))return db.rows.find(x=>x.capture_sha256===this.args[0]&&x.model_sha256===this.args[1])||null;
        if(sql.includes('DESC LIMIT 1'))return db.rows.at(-1)||null;
        if(sql.includes('ASC LIMIT 1'))return db.rows[0]||null;
        throw Error('Unsupported SELECT: '+sql);
      },
      async all() {
        if(sql.includes('WHERE id > ?'))return {results:db.rows.filter(x=>x.id>this.args[0]).slice(0,this.args[1])};
        throw Error('Unsupported ALL: '+sql);
      },
      async run() {
        if(sql.includes('INSERT OR IGNORE')) {
          const [received_at,cutoff_epoch_seconds,capture_sha256,model_sha256,payload_json]=this.args;
          if(!db.rows.some(x=>x.capture_sha256===capture_sha256&&x.model_sha256===model_sha256))
            db.rows.push({id:++db.sequence,received_at,cutoff_epoch_seconds,capture_sha256,model_sha256,payload_json});
          return {success:true};
        }
        if(sql.includes('DELETE')&&sql.includes('received_at <')) {
          db.rows=db.rows.filter(x=>x.received_at>=this.args[0]);return {success:true};
        }
        if(sql.includes('DELETE')&&sql.includes('id NOT IN')) {
          db.rows=db.rows.slice(-this.args[0]);return {success:true};
        }
        throw Error('Unsupported run: '+sql);
      },
    };
  }
}

function post(data, providedToken=token) {
  return new Request('https://my.chatgpt.site/api/live/ingest',{
    method:'POST',
    headers:{Authorization:'Bearer '+providedToken,'Content-Type':'application/json'},
    body:JSON.stringify(data),
  });
}

test('sensor credential check and fixed four-horizon schema',async()=>{
  assert.equal(await sensorAuthorized('Bearer '+token,token),true);
  assert.equal(await sensorAuthorized('Bearer bad',token),false);
  assert.equal(await sensorAuthorized(null,token),false);
  assert.equal(validateSensorPayload(sample()).trajectory.length,4);
  for(const change of [
    {automatic_containment:true},
    {cutoff_epoch_seconds:Date.now()/1000-1000},
    {supported:'yes'},
    {capture_sha256:'not-a-hash'},
    {extra:'new field'},
    {trajectory:[{horizon_seconds:10,malicious_flow_probability:1}]},
  ]){
    assert.throws(()=>validateSensorPayload({...sample(),...change}));
  }
});

test('web route ingests metadata only and cursor feed refuses historical/unsafe inputs',async()=>{
  const env={DB:new FakeDb(),GARUDA_LIVE_SENSOR_TOKEN:token};
  let response=await handleKrishnaLiveRequest(post(sample(),'incorrect'),env);
  assert.equal(response.status,401);
  response=await handleKrishnaLiveRequest(post(sample()),env);
  assert.equal(response.status,202);
  let value=await response.json();
  assert.equal(value.accepted,true);
  assert.equal(value.event_id,1);
  response=await handleKrishnaLiveRequest(new Request('https://my.chatgpt.site/bridge/live/events?after=0'),env);
  assert.equal(response.status,200);
  value=await response.json();
  assert.equal(value.state,'near_live');
  assert.equal(value.events.length,1);
  assert.equal(value.events[0].operating_mode,'SHADOW_ONLY');
  assert.equal(value.events[0].automatic_containment,false);
  assert.equal(value.events[0].score,40);
  assert.equal(value.events[0].capture_sha256,undefined);
  assert.equal(response.headers.has('Access-Control-Allow-Origin'),false);
  response=await handleKrishnaLiveRequest(new Request('https://my.chatgpt.site/bridge/live/events?after=1'),env);
  assert.equal((await response.json()).events.length,0);
  // Repeated publisher retry is idempotent by the two hashes.
  response=await handleKrishnaLiveRequest(post(sample()),env);
  assert.equal(response.status,202);
  assert.equal((await response.json()).event_id,1);
  assert.equal(env.DB.rows.length,1);
  response=await handleKrishnaLiveRequest(post({...sample(),automatic_containment:true}),env);
  assert.equal(response.status,422);
  response=await handleKrishnaLiveRequest(post({...sample(),cutoff_epoch_seconds:1000}),env);
  assert.equal(response.status,422);
  response=await handleKrishnaLiveRequest(new Request('https://my.chatgpt.site/bridge/live/events?after=-1'),env);
  assert.equal(response.status,422);
});

test('unrelated routes are untouched, missing DB fails closed',async()=>{
  assert.equal(await handleKrishnaLiveRequest(new Request('https://my.chatgpt.site/'),{}),null);
  const response=await handleKrishnaLiveRequest(post(sample()),{GARUDA_LIVE_SENSOR_TOKEN:token});
  assert.equal(response.status,503);
});
