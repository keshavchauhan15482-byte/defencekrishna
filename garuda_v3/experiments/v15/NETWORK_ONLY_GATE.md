# V44 strict network-only runtime gate

This branch changes the V15 X-IIoTID feature selector to fail closed.

- Only flow/packet/network telemetry names are eligible.
- Process, PID, thread, CPU, memory, disk, system, kernel, user, sensor, device and similar fields are rejected.
- Labels, timestamps and endpoint identifiers remain excluded.
- Fewer than four usable network columns causes training to stop; it never falls back to a mixed system/network feature set.
- Existing V15 metrics are not reused as V44 results. The experiment must be rerun after this gate.
- V44 is not a production approval: a new network-only checkpoint must also match the live 10-second graph schema and pass a newly reserved campaign holdout.

This is a data-validity fix, not an accuracy guarantee.
