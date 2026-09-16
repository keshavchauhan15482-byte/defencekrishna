# Krishna Defence / Garuda AI — 2-minute demo script

## 0:00–0:15 — Problem

“Traditional IDS tells us what traffic looks malicious now. Garuda AI is built for the SIH world-model challenge: it observes the evolving network state and rolls that state forward before making a defence decision.”

Show the offline console and the recorded/network input selector.

## 0:15–0:40 — Input and world state

“This pipeline ingests flow or raw packet telemetry. V46 represents every 10-second state as a directed graph with 34 flow-and-packet features: TCP flags, traffic volume, IAT statistics, TTL, window size, fragments, payload distribution, port-scan sequencing and retransmission evidence.”

Show the topology/state view and feature panel.

“Unknown truth is never converted to benign, and incomplete packet windows are excluded and audited rather than fabricated.”

## 0:40–1:05 — Forward simulation

“Eight observed windows provide 80 seconds of history. The LSTM and GNN+LSTM world models autoregressively predict the next 10, 20, 30 and 40 seconds. Persistence is included as a baseline, so a learned state model must demonstrate value beyond simply copying the present state.”

Show the rolling future-state/risk timeline.

“The risk head is trained only after the state model passes validation persistence. Thresholding and calibration come from validation traffic, not the final test.”

## 1:05–1:25 — Explainability and stages

“For every supported forecast we expose the traffic features driving the model through gradient-times-input attribution. The architecture also supports supervised Reconnaissance, Initial Access, Lateral Movement, Command-and-Control and Exfiltration outputs. If reviewed stage evidence is missing, the system says insufficient evidence instead of inventing a stage.”

Show top contributing features and the stage/insufficient-evidence panel.

## 1:25–1:45 — Defence

“Forecast evidence is routed through three controlled defence layers. Arjuna handles reviewed known attacks. Krishna keeps novel or unsupported patterns in a review-and-learning lane. Sudarshana provides scoped, time-limited operator-approved lockdown in the lab, with signed policy, audit and revoke controls.”

Trigger only the safe recorded/lab response demonstration.

## 1:45–2:00 — Evidence boundary

“Our first 34-feature cross-family diagnostic is intentionally fail-closed: it shows strong validation state learning but does not yet beat persistence on the exposed botnet/infiltration test, and no model passes our final one-percent-FPR/eighty-percent-recall gate. We report that failure because the next step is verified unseen campaigns and compromise timelines—not a fabricated accuracy claim.”

End on the architecture + release-gate screen.
