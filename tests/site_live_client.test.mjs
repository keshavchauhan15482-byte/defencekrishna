import assert from 'node:assert/strict';
import test from 'node:test';
import {createKrishnaSiteLiveClient} from '../site_integration/chatgpt_sites/live_client.mjs';

test('one graph event per real incoming sensor id, no fabricated replay points',async()=>{
  const seen=[],statuses=[],errors=[],urls=[];
  const event={id:1,kind:'forecast',score:32.1,
    trajectory:[10,20,30,40].map((n,i)=>({horizon_seconds:n,malicious_flow_probability:i/10})),
    automatic_containment:false};
  let n=0;
  const fetchImpl=async url=>{
    urls.push(url);
    n++;
    return new Response(JSON.stringify({
      state:n===1?'near_live':'stale',events:n===1?[event,event]:[],
      sensor_age_seconds:n===1?3:180,gap:false,
    }),{status:200,headers:{'Content-Type':'application/json'}});
  };
  const client=createKrishnaSiteLiveClient({
    fetchImpl,onEvent:x=>seen.push(x),onState:x=>statuses.push(x),onError:e=>errors.push(e)
  });
  await client.poll();
  assert.equal(seen.length,1);
  assert.equal(client.getCursor(),1);
  await client.poll();
  assert.equal(seen.length,1);
  assert.deepEqual(urls,['/bridge/live/events?after=0','/bridge/live/events?after=1']);
  assert.equal(statuses[1].state,'stale');
  assert.equal(statuses[1].advisoryOnly,true);
  assert.deepEqual(errors,[]);
});

test('non-shadow/unsafe event never drives a model display',async()=>{
  const seen=[],errors=[];
  const fetchImpl=async()=>new Response(JSON.stringify({
    state:'near_live',events:[{id:1,kind:'forecast',trajectory:[{}, {}, {}, {}],
      automatic_containment:true}]
  }),{status:200});
  const client=createKrishnaSiteLiveClient({
    fetchImpl,onEvent:x=>seen.push(x),onError:e=>errors.push(e)
  });
  await client.poll();
  assert.equal(seen.length,0);
  assert.equal(client.getCursor(),0);
  assert.equal(errors.length,1);
});

test('disabled/waiting status carries no synthetic score or event',async()=>{
  const states=[],events=[];
  const fetchImpl=async()=>new Response(JSON.stringify({state:'waiting',events:[],
    sensor_age_seconds:null,gap:false}),{status:200});
  const client=createKrishnaSiteLiveClient({
    fetchImpl,onState:s=>states.push(s),onEvent:e=>events.push(e)
  });
  await client.poll();
  assert.equal(states[0].state,'waiting');
  assert.equal(events.length,0);
  assert.throws(()=>createKrishnaSiteLiveClient({intervalMs:0}));
});
