/* Shared pure view policy; browser UMD + Node regression tests. */
(function(root){
"use strict";
function classify(event,feed,now){
 const none=(state,reason)=>({state,reason,active:false,remaining:[],expiresAt:null});
 if(!feed||feed.online!==true)return none("OFFLINE","Cloud forecast feed unavailable");
 if(!event)return none("WAITING","No genuine model forecast received");
 const p=event.trajectory,c=event.cutoff_epoch_seconds;
 const valid=Array.isArray(p)&&p.length===4&&[10,60].some(step=>p.every((x,i)=>x?.horizon_seconds===step*(i+1)&&Number.isFinite(x.malicious_flow_probability)&&x.malicious_flow_probability>=0&&x.malicious_flow_probability<=1));
 if(!valid||!Number.isFinite(c)||c<=0||!Number.isFinite(now)||now<c)return none("INVALID","Forecast timestamp or horizon invalid");
 const expiresAt=c+p[3].horizon_seconds;
 const remaining=p.filter(x=>c+x.horizon_seconds>now);
 const result=(state,reason,active=false)=>({state,reason,active,remaining:active?remaining:[],expiresAt});
 if(feed.gap!==false)return result("GAP","Forecast stream continuity unverified");
 if(event.supported!==true)return result("UNSUPPORTED","Model input outside verified support");
 if(now>=expiresAt)return result("EXPIRED","All forecast horizons have elapsed");
 if(feed.state!=="near_live")return result("STALE","Capture feed is not current");
 const h=feed.sensor_status;
 if(!["capturing","processing"].includes(h?.state)||!Number.isFinite(h.sensor_age_seconds)||h.sensor_age_seconds<0||h.sensor_age_seconds>=90)return result("STALE","Sensor heartbeat missing or stale");
 return result("ACTIVE_ADVISORY","Supported forecast window open; advisory only",true);
}
const api={classify};
if(typeof module!=="undefined"&&module.exports)module.exports=api;
else root.KrishnaForecastView=api;
})(typeof globalThis!=="undefined"?globalThis:this);
