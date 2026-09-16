# V44 strict network-only runtime gate

V44 is a new versioned experiment. It does **not** mutate the archived V15 evidence source.

- Only flow/packet/network telemetry is eligible for the V44 research input gate.
- Process, PID, thread, CPU, memory, disk, system, kernel, user, sensor, device and similar fields are rejected.
- Labels, timestamps and endpoint identifiers are excluded from tabular research features.
- Fewer than four usable network columns causes training to stop; V44 never falls back to mixed system/network telemetry.
- The deployable path must use the exact live `garuda-observed-graph-v3.1` contract: 21 canonical network/packet features, 10-second windows and max 32 nodes.
- Existing V15 metrics are not reused as V44 results.
- Checked-in IDS2018 captures may be used for runtime-regression evidence, but because they were used previously they are not a newly untouched final holdout.
- Automatic unknown containment remains disabled until a newly predeclared holdout, verified clean-history onset evidence and the remaining release gates pass.

This is a data-validity and runtime-compatibility gate, not an accuracy guarantee.
