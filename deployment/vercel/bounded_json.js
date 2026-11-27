"use strict";
const MAX_FEED_BYTES=131072;

// Bound decoded HTTP body bytes during streaming, including chunked responses.
// Never trust Content-Length as the only size control.
async function readBoundedJson(response,limit=MAX_FEED_BYTES){
  if(!Number.isSafeInteger(limit)||limit<1||limit>MAX_FEED_BYTES)throw Error("Invalid limit");
  const declared=response.headers.get("content-length");
  if(declared!==null&&(!/^\d+$/.test(declared)||Number(declared)>limit)){
    if(response.body)await response.body.cancel().catch(()=>{});
    throw Error("Upstream response too large or invalid length");
  }
  if(!response.body)throw Error("Missing upstream body");
  const reader=response.body.getReader();
  const decoder=new TextDecoder("utf-8",{fatal:true});
  let bytes=0,text="",complete=false;
  try{
    while(true){
      const {done,value}=await reader.read();
      if(done){complete=true;break;}
      bytes+=value.byteLength;
      if(bytes>limit)throw Error("Upstream response too large");
      text+=decoder.decode(value,{stream:true});
    }
    text+=decoder.decode();
    return JSON.parse(text);
  }finally{
    if(!complete)await reader.cancel().catch(()=>{});
    reader.releaseLock();
  }
}
module.exports={readBoundedJson,MAX_FEED_BYTES};
