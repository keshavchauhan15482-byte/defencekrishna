"""Conservative observed-behaviour hints. No calibrated probabilities or ML stage claims."""
import ipaddress
import numpy as np
from .data import FEATURES

def infer_stage_hint(graph, alert=False):
    x=np.asarray(graph['x'],dtype=float)[-1];a=np.asarray(graph['adj'],dtype=float)[-1]
    active=np.asarray(graph['mask'])[-1].astype(bool);names=graph.get('node_names',[])
    syn=x[:,FEATURES.index('syn_fraction')];ack=x[:,FEATURES.index('ack_fraction')]
    base=dict(method='heuristic_observed_v1',ml_trained=False,validated=False,
              temporal_scope='Observed history, not a predicted future tactic',confidence=None,
              caveat='Investigative hint only. Benign administration and scanning can match these rules. No rule match does not mean benign.')
    # adj[target, source] is directed. Host attribution only with genuine endpoint graphs.
    if graph.get('mode')=='host':
        for i in np.where(active)[0]:
            destinations=int(np.count_nonzero(a[:,i]));
            if syn[i]>=.5 and ack[i]<=.2 and destinations>=8:
                try:internal=ipaddress.ip_address(names[i]).is_private
                except (ValueError,IndexError):internal=None
                tactic='Discovery' if internal else 'Reconnaissance' if internal is False else 'Scanning review'
                tech='T1046' if internal else 'T1595'
                return dict(base,title=tactic+' candidate',tactic=tactic,technique=tech,
                    rule='syn >= 0.50 AND ack <= 0.20 AND observed destinations >= 8',
                    evidence=[dict(feature='syn_fraction',value=float(syn[i])),dict(feature='ack_fraction',value=float(ack[i])),dict(feature='observed_destinations',value=destinations)],
                    source_node=names[i] if i<len(names) else str(i),reference='https://attack.mitre.org/techniques/'+tech+'/')
    ports=[n for i,n in enumerate(names) if i<len(active) and active[i] and n.startswith('service:')]
    if graph.get('mode')=='service' and len(ports)>=6 and float(syn[active].mean())>=.5:
        return dict(base,title='Broad service probing',tactic=None,technique=None,
                    rule='active service categories >= 6 AND mean SYN fraction >= 0.50',
                    evidence=[dict(feature='active_service_categories',value=len(ports)),dict(feature='mean_syn_fraction',value=float(syn[active].mean()))],
                    reference='https://attack.mitre.org/techniques/T1595/',
                    caveat=base['caveat']+' Aggregate service nodes cannot attribute scanning to a host.')
    remote=[n for n in ports if n in ('service:22','service:445','service:3389')]
    if alert and remote:
        return dict(base,title='Remote-service activity review',tactic=None,technique=None,
                    rule='forecast alert AND observed SSH, SMB or RDP service category',
                    evidence=[dict(feature='observed_remote_services',value=remote)],
                    caveat=base['caveat']+' A port alone cannot establish Initial Access or Lateral Movement.')
    return dict(base,title='Suspicious activity review' if alert else 'No specific stage evidence',tactic=None,technique=None,
                rule='No specific observed-behaviour rule matched',evidence=[])
