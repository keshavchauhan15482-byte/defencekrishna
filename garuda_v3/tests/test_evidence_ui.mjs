import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source=fs.readFileSync(new URL('../ui/console-v132-extra.js',import.meta.url),'utf8');
const marker='// Keep the independent-source evidence separate';
assert.ok(source.includes(marker));
const addition=source.slice(source.indexOf(marker));
class Element{
 constructor(tag){this.tag=tag;this.children=[];this.textContent='';}
 append(...nodes){this.children.push(...nodes);}
}
async function mount(response){
 const host=new Element('host');let requested;
 vm.runInNewContext(addition,{
  document:{readyState:'complete',getElementById:id=>id==='benchmarks'?host:null,createElement:tag=>new Element(tag)},
  fetch:async url=>{requested=url;return response;}
 });
 await new Promise(setImmediate);
 return {host,requested};
}
function descendants(node,tag){return [...(node.tag===tag?[node]:[]),...node.children.flatMap(n=>descendants(n,tag))];}
function evidence(){return {schema:'published-comparison-v1',live_model_metrics:false,scope:'V88 two episodes',
 metrics:Object.fromEntries(['precision','recall','f1','fpr'].map(k=>[k,{logistic_regression:.5,garuda:.9}]))};}

test('console renders all four matched metrics in a separately scoped table',async()=>{
 const {host,requested}=await mount({ok:true,json:async()=>evidence()});
 assert.equal(requested,'/bridge/evidence');
 assert.equal(descendants(host,'th').length,5);
 assert.equal(descendants(host,'td').length,10);
 assert.match(descendants(host,'p')[0].textContent,/Does not establish five-stage/);
});
test('offline endpoint never substitutes invented scores',async()=>{
 const {host}=await mount({ok:false});
 assert.equal(descendants(host,'table').length,0);
 assert.match(descendants(host,'p')[0].textContent,/No replacement or estimated metrics/);
});
test('partial response fails closed without a partial metric table',async()=>{
 const d=evidence();delete d.metrics.f1;
 const {host}=await mount({ok:true,json:async()=>d});
 assert.equal(descendants(host,'table').length,0);
});
