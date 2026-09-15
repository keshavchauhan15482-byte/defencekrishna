# Two-minute demonstration recording script

This is a recording plan, not a completed video. Screen-record the real local dashboard.

| Time | Screen action | Narration |
|---|---|---|
| 0:00-0:15 | Show title and model status | “Krishna Defence models observed network traffic as graphs and forecasts four future windows. We focus on evidence and explainable response.” |
| 0:15-0:35 | Click Run held-out replay | “This is an actual held-out capture replay. Protocol/service edges come from the supplied flow records. We do not invent host identities that are absent from the CSV.” |
| 0:35-0:55 | Point to graph and timeline | “Directed GraphSAGE learns observed relationships. An LSTM learns temporal context. The autoregressive decoder predicts future state distributions and malicious-flow scores.” |
| 0:55-1:10 | Show feature sensitivity and unknown stage | “These feature contributions explain this exact prediction. Stage labels remain unresolved because our data has Bot/Benign labels rather than incident-stage annotations.” |
| 1:10-1:30 | Show measured evidence table | “The primary internal test gives 94.4% F1 for GNN plus LSTM, compared with 91.6% for logistic regression. The clean-history onset sample is too limited to claim pre-compromise warning.” |
| 1:30-1:45 | Operator policy dry-run, or isolated lab test | “A forecast cannot automatically block traffic. Operators choose a bounded scope and expiry. Signed proxy rules support revoke and a kill switch.” |
| 1:45-2:00 | Show final PPTX slide | “Next we need endpoint-preserving captures and annotated incident timelines to validate attack-stage progression, unseen-campaign performance and enterprise deployment.” |

Before recording: install dependencies, launch the service, connect, and keep tokens off camera. Use the new deck and v3 dashboard rather than legacy reports. Do not claim that 94.4% F1 means 94.4% chance of stopping a breach. Do not claim the diagram reconstructs missing host topology. There is no hosted source URL or completed demo video in this handoff; publish to your chosen repository and record locally after review.
