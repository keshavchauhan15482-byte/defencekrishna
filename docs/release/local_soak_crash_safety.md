# Local endurance and crash safety

No public listener, public tunnel or deployment is introduced. Repository
visibility is unchanged. Only isolated fixture runtimes and owned child processes
are exercised; no customer traffic or third-party attacks are used.

## Reproduced faults and fixes

On parent main `22eba5c34189df8366cbc81d40bec5f2143e2f67`, new regression tests
reproduced policy reactivation after a forced exit between SQLite commit and
policy-file publication, and automatic policy resumption on a normal restart.
The publication-fault safety latch was also absent. These were software-control
faults, not claims that an attacker compromised the model.

- **Restart requires reapproval.** After checking audit integrity, startup revokes
  all old active policy records, appends a counted audit event and publishes an
  empty policy envelope. Previously existing policies are NOT automatically resumed.
  This intentional behavior change applies to local and pilot PolicyStore startup.
- **Publication faults latch safe mode.** Filesystem publication failures and SQL
  mutation failures inhibit new policy proposals. Subsequent file publications
  contain no active policies. Authenticated readiness returns 503 while latched;
  an operator must investigate, restart and approve new policies explicitly.
- **Durable publication.** Random private temporary files replace the fixed temp
  filename; the file is fsynced, atomically replaced and the containing directory
  is fsynced on POSIX.
- **Pilot single-writer ownership.** A nonblocking POSIX OS lock protects the
  runtime folder. Duplicate pilot owners reject startup. OS release after an
  actual child-process kill is tested; failed App/IntegratedApp initialization
  closes database/ownership handles. The lock inode is not deleted on close.
  Local non-pilot compatibility paths still assume one trusted writer; this is
  not protection against a malicious local administrator bypassing the API.
- **Recorded replay budget.** `/bridge/replay` now shares a 60-per-minute replay
  quota per runtime, before model inference or audit writes. A single console's
  default 2.6-second polling remains below the budget. It is a shared quota, not
  multi-tenant fairness or a customer-scale capacity claim.

The gate is fail-closed for **authorization to create new containment**, not a
deny-all/fail-closed data plane. Clearing policies can allow traffic. An already
running downstream proxy may retain its last verified policy until it sees a valid
update or TTL expires. A disk outage cannot guarantee instantaneous emergency
revocation. Publication still needs downstream enforcement confirmation; signing
is not encryption of customer traffic or proof of breach prevention.

## Endurance runner

```sh
GARUDA_DEPLOYMENT_PROFILE=pilot python -m garuda_v3.local_soak --seconds 300 --workers 4 --output /tmp/krishna-soak-5m.json
```

This foreground runner:

1. Creates an isolated temporary runtime with ephemeral credentials, starts the
   actual integrated server bound to loopback, and loads the pinned risk checkpoint.
2. Sends bounded concurrent status/health requests, recorded shadow replay,
   repeated explicitly synthetic CSV uploads and authenticated readiness checks.
   Upload results must contain finite advisory forecasts and no automatic action.
3. Abruptly kills **only its own child process** halfway through, between requests,
   restarts the same fixture runtime, checks checkpoint identity, shadow mode and
   empty policies, then continues. Dedicated regression additionally forces exit
   in the policy commit/publication gap; the soak kill is not a random mid-write test.
4. Samples actual Linux child RSS, CPU time, thread and file-descriptor counts.
   Per-process segments avoid falsely treating restart memory reset as improvement.
   Measurements unavailable on non-Linux hosts are not silently replaced by zero.
5. Performs an online encrypted snapshot and offline restore; audit integrity must
   verify and no policy may reactivate. This does not exercise an actual full disk.

Source hashes for boundary modules and runner are frozen and checked after the
run. The report records loaded Python/NumPy versions, checkpoint hash, actual wall
duration, request counts and per-segment resources. Model weights are unchanged.

Explicit development smoke thresholds are RSS growth at most 32 MiB from the
10-sample warmed baseline per process (initial sample if shorter), at most 24
threads and 128 descriptors, no unexpected HTTP statuses, successful restart and
verified recovery. These are transparent runner gates, not justified customer SLAs
or proof that a long-lived memory leak is absent. CPU is reported, not gated.

Memory use in the runner is bounded: it retains the last 4,096 request latencies
and last 720 resource samples, with lifetime per-segment resource peaks. For long
runs, reported latency percentiles cover the retained tail, not every request.
Output reports are create-only; interruptions/exceptions emit FAIL when an output
can be written. Ephemeral fixture logs are sent to the null sink, not accumulated
in RAM; the real service's configured operational logging is not disabled.

## What evidence exists versus what remains

Frozen-source measured run (Python 3.12.14 / NumPy 2.3.5, four workers):

| Observation | Result |
|---|---:|
| Actual wall duration | 300.001 seconds |
| Successful HTTP responses | 1,296 / 1,296; zero unexpected statuses |
| Workload mix | 1,200 status/health; 60 recorded replays; 15 synthetic CSV uploads; 20 readiness; 1 restart check |
| Median / p95 latency, all retained requests | 5.839 / 20.894 ms |
| Peak child RSS | 41,048 KiB (40.09 MiB) |
| Warmed-to-final RSS growth, process 1 / 2 | 3,328 / 4,760 KiB |
| Maximum sampled threads / descriptors | 2 / 11 |
| Sampled cumulative CPU time, process 1 / 2 | 2.80 / 3.19 seconds |
| Abrupt restart / encrypted recovery | Passed; audit verified; zero policies reactivated |
| Frozen source hashes | Unchanged |

Most requests are cheap operational reads, not forecasts or attacks. RSS did grow
within the explicit smoke budget; these observations do not establish absence of
a memory leak or performance under customer traffic. The two process segments
must not be pooled as if restart lowered a single process's resource use.

The committed `local_soak_verified_20261116.json` is a **five-minute local run**.
It must not be presented as 8–24-hour endurance, enterprise capacity, attack
blocking efficacy, cross-campaign model generalization or verified lead time.
Synthetic upload timestamps are fixture values, not new dataset/incident truth.
The small 20-second CI version only prevents integration regressions.

For an actual eight-hour foreground run on an owned local Linux test machine:

```sh
GARUDA_DEPLOYMENT_PROFILE=pilot python -m garuda_v3.local_soak --seconds 28800 --workers 4 --output /private/test-results/krishna-soak-8h.json
```

Use a new output path, install base and optional pilot requirements, retain the
source checkout unchanged during the run and keep it local. This release does not
schedule an unattended long run. Real filesystem exhaustion, power-loss recovery,
telemetry freshness, customer concurrency/capacity, backup RPO/RTO, fresh forecasting
qualification and independent security review remain separate acceptance gates.
