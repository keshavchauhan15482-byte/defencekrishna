# V102 MAWI external one-shot closure

V102 preregistered MAWI Samplepoint-B capture `200601011400.dump` only after the V101 packet-compatible GraphSAGE+LSTM candidate was frozen. Source hashes were acquired and committed before packet-record decoding or model inference.

The one-shot was consumed by a pre-inference lock in GitHub Actions run `36308007599`. The frozen evaluator then rejected a packet record with `V102ContractError: Invalid PCAP capture/original length` during classic-PCAP decoding, before graph sequence construction and before model-forward/state-MSE computation.

Therefore V102 is **INCOMPATIBLE_AFTER_CONSUMPTION**, not a forecasting PASS or FAIL. MAWI must not be retried or used to tune the parser, adapter, model, normalization, support gate, threshold, checkpoint, or any future external claim. Parser hardening must use standards/specification and synthetic or non-MAWI development evidence, followed by a different untouched external holdout.
