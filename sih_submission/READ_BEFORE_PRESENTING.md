# Previous presentation artifacts

The PPTX, PDF and recording script in this folder describe the **previous absolute-decoder revision**. They have not been re-exported for the residual update. Do not present their numerical results as the current model.

Use `../garuda_v3/FIX_STATUS.md` and the current dashboard metrics for the updated evidence. Current primary: seed 42, residual GNN, final-window F1 94.87%, state MSE 0.0127064 versus persistence 0.0127354. The primary improvement is small and uncertain. Pre-compromise warning remains unproven; actual host/packet-stage training requires additional annotated data. The LSTM baseline currently outperforms GNN on this service-only data.

The new implementation adds residual dynamics, incident-level evaluation, campaign splits, and supervised multi-label MITRE training/inference. Do not describe synthetic integration tests as real-world attack evidence.

Console 5 supplies CrossDay_Pilot_Roadmap.pptx as an updated replacement roadmap slide. The original five-slide deck is retained and is not otherwise revised by this release.
