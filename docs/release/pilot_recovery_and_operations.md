# Pilot recovery and operations — implementation and measured evidence

## Implemented, not certified

This release adds encrypted recovery, disk-space readiness, bounded operational
metrics and reproducible localhost rehearsal. It does not configure customer
SSO/TLS, deliver multi-tenant SaaS, prove forecast accuracy or authorize blocking.
Use separate OS processes, service accounts, directories and credentials per
customer. Tenant names inside backups are integrity-bound identifiers, not an
access-control or multi-tenant isolation system.

## Encrypted backup and offline restore

Use Python 3.11+ on POSIX (tested with Python 3.12) and install
`garuda_v3/requirements-pilot.txt` in the service environment. Generate a
dedicated random 32-byte key in a private file owned by the service account:

```sh
umask 077
openssl rand -out /secure/customer-a-backup.key 32
python -m garuda_v3.runtime_backup backup --runtime /srv/krishna/customer-a --archive /backups/customer-a-001.enc --key-file /secure/customer-a-backup.key --tenant customer-a
python -m garuda_v3.runtime_backup restore --runtime /srv/krishna/customer-a-restored --archive /backups/customer-a-001.enc --key-file /secure/customer-a-backup.key --tenant customer-a
```

Paths are examples; create appropriate private parent directories first. Never
overwrite an existing key. Keep independent backup-key escrow under customer
control, separate from archives and runtime credentials. Losing it loses recovery;
the tool cannot recover a lost key. Rotate archive keys using a reviewed procedure.

- POSIX permission checks require private regular key files, exact length and
  ownership; symlink keys are rejected. Do not pass key bytes on a command line.
- SQLite online backup obtains a consistent snapshot, including WAL writes.
  SQLite integrity and audit chaining are checked before AES-256-GCM encryption.
  Database plaintext is held in memory, not written to a temporary plaintext file.
  The tool does not guarantee memory zeroization, encrypted swap or encrypted RAM.
- Encrypted metadata binds tenant, database SHA-256 and audit head/count. Wrong
  key, altered ciphertext, wrong tenant or bad audit rejects restoration.
- Archives publish atomically without overwriting existing files. Restore requires
  a new directory, creates private files and leaves an incomplete-restore marker
  on interrupted writes. App startup refuses marked directories.
- Restores append an audit event and revoke all active policies. No access tokens,
  signing keys, published policy file, lab arming or model artifacts are restored.
  Start with `GARUDA_DEPLOYMENT_PROFILE=pilot`; provision new credentials separately.
- Pilot limit: **32 MiB database**, 15-second snapshot progress budget. This is not
  a general-purpose unlimited enterprise backup service. Larger databases must use
  a reviewed backup design. No automatic deletion or retention policy is enabled.
- A correctly rehashed/truncated local chain cannot be detected without an
  independent trusted anchor. AES authentication proves archive integrity under
  the backup key, not truthfulness or completeness of the original events.

## Monitor operational health

- `/health`: liveness only. Do not treat this as readiness.
- Authenticated `/api/readiness`: audit integrity and free-space gate; HTTP 503 on
  failure. Default free-space budget is 64 MiB; set `GARUDA_MIN_FREE_BYTES` to an
  explicitly sized positive budget (1 MiB..1 TiB).
- Authenticated `/api/operations`: completed/in-flight requests, status classes,
  fixed latency buckets, uptime and bounded-thread capacity rejections. No URL,
  credential, attack label or tenant-labelled high-cardinality series is collected.
  Counters reset at process restart. They are not detection accuracy measurements.
- Use an external authenticated monitor to poll readiness, alert on non-200,
  repeated 5xx, capacity rejections, elevated latency or stalled telemetry. No
  pager destination or customer observability backend has been configured here.
  Readiness does **not** certify telemetry freshness or gateway availability.

## Reproduce a safe rehearsal

```sh
GARUDA_DEPLOYMENT_PROFILE=pilot python -m garuda_v3.pilot_rehearsal --output /tmp/krishna-pilot-rehearsal.json
python -m pytest garuda_v3/tests/test_runtime_backup.py garuda_v3/tests/test_operations.py garuda_v3/tests/test_runtime_guard.py -q
```

The rehearsal uses an isolated temporary runtime, ephemeral tokens and the bundled
recorded replay. It never sends attacks to remote systems. Maximum 50 requests,
8 workers; default 40 requests/4 workers. Reports are create-only. Do not call
these small localhost checks production load/soak or predictive-performance tests.

Committed measured run: `pilot_rehearsal_20261116.json`.

| Check | Observed in this environment |
|---|---:|
| Local operational requests | 40/40 HTTP 200, four workers |
| Median / p95 latency | 4.947 / 8.463 ms |
| Unauthenticated console | HTTP 401 |
| Recorded replay | HTTP 200; no automatic containment |
| Encrypted snapshot / restore | 22.719 / 2.500 ms; tiny 33,100-byte fixture archive |
| Restored audit | Verified; zero policies reactivated; no credentials restored |

Timings are single-run environment-specific observations, not SLAs or enterprise
capacity claims. Fault tests cover wrong keys, ciphertext corruption, cross-tenant
restore, concurrent WAL writes, existing destinations, simulated disk-full failure,
incomplete restore startup rejection and low-disk readiness.

## Remaining customer acceptance dependencies

1. Customer hostname, certificate/identity-provider configuration and approved
   role/group mapping are needed to implement and test actual TLS/SSO gateway
   sessions, logout and CSRF boundaries. No provider is guessed or bypassed.
2. Customer-approved backup RPO/RTO, retention/erasure policy, key escrow and alert
   destination; then schedule and rehearse on real customer-sized data.
3. Long-running load/soak, process-kill, actual filesystem exhaustion and host
   recovery tests in a disposable deployment. Unit fault injection is not a real
   disk-exhaustion exercise.
4. An independent security/dependency review is still external work, not something
   the implementation can self-certify. Fresh forecasting qualification still
   requires untouched campaigns and independently verified incident timestamps.

## Primary implementation references

- https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup
- https://sqlite.org/c3ref/deserialize.html (WAL snapshot rollback-format handling)
- https://cryptography.io/en/50.0.2/hazmat/primitives/aead/ (AES-GCM)
