"use strict";
// Fixed inert educational fixture records. No packet generation, sockets,
// target addresses, user-controlled signals, execution or policy changes.
const FIXTURES=Object.freeze({
  "syn_flood":Object.freeze({signal:"known",reason:"DEMO_SYN_FLOOD"}),
  "port_scan":Object.freeze({signal:"known",reason:"DEMO_PORT_SCAN"}),
  "lateral_smb":Object.freeze({signal:"scope",reason:"DEMO_LATERAL_SMB"}),
  "burst_ddos":Object.freeze({signal:"known",reason:"DEMO_DDOS_BURST"}),
  "dns_tunnel":Object.freeze({signal:"review",reason:"DEMO_DNS_TUNNEL"}),
  "c2_beacon":Object.freeze({signal:"review",reason:"DEMO_C2_BEACON"}),
  "exfil_spike":Object.freeze({signal:"scope",reason:"DEMO_EXFIL_SPIKE"}),
  "hospital_availability":Object.freeze({signal:"known",reason:"DEMO_HOSPITAL_AVAILABILITY"}),
  "hospital_anomaly":Object.freeze({signal:"review",reason:"DEMO_HOSPITAL_ANOMALY"}),
  "hospital_private":Object.freeze({signal:"scope",reason:"DEMO_HOSPITAL_PRIVATE"}),
  "clean_baseline":Object.freeze({signal:"normal",reason:"DEMO_BASELINE_ALLOWED"})
});
function inspectScenarioRecord(record){
 if(typeof record!=="string"||!record.startsWith("lab-"))return null;
 const key=record.slice(4);
 if(!Object.hasOwn(FIXTURES,key))return null;
 const f=FIXTURES[key];
 const lane={known:"ARJUNA",review:"KRISHNA",scope:"SUDARSHAN",normal:"ARJUNA"}[f.signal];
 const allowed=f.signal==="normal";
 return {allowed,status:allowed?200:403,lane,reason:f.reason,engine:"scenario-fixture-policy",scenario:key,scope:"synthetic_scenario_policy_only"};
}
module.exports={inspectScenarioRecord};
