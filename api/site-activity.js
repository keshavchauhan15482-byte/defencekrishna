"use strict";
/**
 * First-party website HTTP activity only. The browser cannot send events to
 * Render directly, choose arbitrary telemetry fields, or access credentials.
 * Logged activity is a request count, NOT a unique visitor or AI prediction.
 */
const {randomUUID}=require("node:crypto");

module.exports=async function handler(request,response){
  response.setHeader("Cache-Control","no-store");
  response.setHeader("X-Content-Type-Options","nosniff");
  response.setHeader("Cross-Origin-Resource-Policy","same-origin");
  if(request.method!=="POST")return response.status(405).json({error:"POST required"});
  const origin=request.headers?.origin;
  const host=request.headers?.host;
  const fetchSite=request.headers?.["sec-fetch-site"];
  // Website-originated requests only; arbitrary third-party embeds are denied.
  if(typeof origin!=="string"||typeof host!=="string"||
     origin!==("https://"+host)||fetchSite==="cross-site"){
    return response.status(403).json({error:"Same-origin browser request required"});
  }
  const bodyLength=Number(request.headers?.["content-length"]||0);
  if(!Number.isFinite(bodyLength)||bodyLength!==0||
     (request.body&&Object.keys(request.body).length>0)){
    return response.status(413).json({error:"Request payload not accepted"});
  }
  const secret=process.env.RENDER_ACTIVITY_TOKEN;
  const base=process.env.RENDER_BACKEND_URL;
  if(!secret||secret.length<32||!base)return response.status(503).json({error:"Site telemetry not configured"});
  let endpoint;
  try{
    const url=new URL(base);
    if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||
       (url.pathname!=="/"&&url.pathname!==""))throw Error("Unsafe backend");
    endpoint=new URL("/api/site-activity/ingest",url);
  }catch{
    return response.status(503).json({error:"Site telemetry backend misconfigured"});
  }
  try{
    const upstream=await fetch(endpoint,{
      method:"POST",headers:{
        "Authorization":"Bearer "+secret,
        "Content-Type":"application/json",
        "Accept":"application/json",
      },
      body:JSON.stringify({
        schema:"krishna-site-activity-v1",kind:"page_load",
        request_uuid:randomUUID(),
      }),
      redirect:"error",signal:AbortSignal.timeout(15_000),cache:"no-store",
    });
    if(upstream.status!==202)throw Error("Telemetry rejected");
    return response.status(202).json({recorded:true,mode:"HTTP_ACTIVITY_ONLY"});
  }catch{
    return response.status(503).json({error:"Site telemetry temporarily unavailable"});
  }
};
