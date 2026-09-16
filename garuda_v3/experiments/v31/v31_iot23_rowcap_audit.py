from __future__ import annotations

"""V31 support-only audit for the IoT-23 row cap.

No model is trained and no performance metric is selected. Each official
IoT-23 conn.log.labeled stream is read once up to 300k valid rows, with a
100k snapshot retained. We compare the exact temporal support needed by the
V23-V30 protocol: clean 8-minute histories, 4-minute futures, one-hour block
eligibility, and clean-onset development-family candidates.
"""

import json
import re
import urllib.request
from pathlib import Path

BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
OUT = Path(__file__).resolve().parent / "artifacts" / "iot23_rowcap_audit"
OUT.mkdir(parents=True, exist_ok=True)

WINDOW_SECONDS = 30
HISTORY_WINDOWS = 16
FUTURE_WINDOWS = 8
BLOCK_SECONDS = 3600
CHECKPOINTS = (100_000, 300_000)
MAX_ROWS = max(CHECKPOINTS)
DEV_FAMILIES = ("c&c-heartbeat", "c&c", "partofahorizontalportscan")


def scenarios() -> list[str]:
    req = urllib.request.Request(BASE_URL, headers={"User-Agent": "KrishnaDefence-V31/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        html = r.read().decode("utf-8", errors="ignore")
    return sorted(set(re.findall(r'href="(CTU-IoT[^"]+/)"', html)))


def parse_label(field: str) -> tuple[bool, str]:
    parts = field.strip().split()
    if len(parts) < 3:
        return False, "unknown"
    malicious = parts[1].strip().lower() == "malicious"
    detail = parts[2].strip().lower() if malicious else "benign"
    return malicious, detail


def clone_bins(bins: dict[int, dict]) -> dict[int, dict]:
    return {
        int(ts): {"attack": bool(v["attack"]), "families": set(v["families"])}
        for ts, v in bins.items()
    }


def stream_snapshots(sc: str) -> tuple[dict[int, dict[int, dict]], int]:
    url = f"{BASE_URL}{sc}bro/conn.log.labeled"
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V31/1.0"})
    bins: dict[int, dict] = {}
    snapshots: dict[int, dict[int, dict]] = {}
    total = 0
    with urllib.request.urlopen(req, timeout=120) as r:
        for raw in r:
            line = raw.decode("utf-8", errors="ignore").rstrip("\n")
            if not line or line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 21:
                continue
            try:
                ts = float(p[0])
            except Exception:
                continue
            b = int(ts // WINDOW_SECONDS) * WINDOW_SECONDS
            item = bins.setdefault(b, {"attack": False, "families": set()})
            malicious, detail = parse_label(p[-1])
            if malicious:
                item["attack"] = True
                item["families"].add(detail)
            total += 1
            if total in CHECKPOINTS:
                snapshots[total] = clone_bins(bins)
                print(f"V31 SNAPSHOT {sc.rstrip('/')} rows={total} bins={len(bins)}", flush=True)
            if total >= MAX_ROWS:
                break
    final = clone_bins(bins)
    for cap in CHECKPOINTS:
        if cap not in snapshots:
            snapshots[cap] = final
    return snapshots, total


def filled_timeline(bins: dict[int, dict]):
    if not bins:
        return [], [], []
    lo, hi = min(bins), max(bins)
    times, attacks, families = [], [], []
    for b in range(lo, hi + WINDOW_SECONDS, WINDOW_SECONDS):
        item = bins.get(b)
        times.append(b)
        if item is None:
            attacks.append(False)
            families.append(set())
        else:
            attacks.append(bool(item["attack"]))
            families.append(set(item["families"]))
    return times, attacks, families


def eligible_cutoff(times: list[int], i: int) -> bool:
    start = times[0]
    local = int(times[i] - start)
    pos = local % BLOCK_SECONDS
    return bool(
        pos >= (HISTORY_WINDOWS - 1) * WINDOW_SECONDS
        and pos <= BLOCK_SECONDS - FUTURE_WINDOWS * WINDOW_SECONDS - WINDOW_SECONDS
    )


def analyze_bins(bins: dict[int, dict]) -> dict:
    times, attacks, famsets = filled_timeline(bins)
    if not times:
        return {
            "bins": 0, "span_minutes": 0.0, "usable_12min": False,
            "clean_history_sequences": 0, "clean_future_positive_sequences": 0,
            "families": {f: {"clean_onset_events": 0, "evaluable_events": 0, "candidate_windows": 0} for f in DEV_FAMILIES},
        }

    clean_sequences = 0
    clean_future_positive = 0
    for i in range(HISTORY_WINDOWS - 1, len(times) - FUTURE_WINDOWS):
        if not eligible_cutoff(times, i):
            continue
        lo = i - HISTORY_WINDOWS + 1
        clean = not any(attacks[lo:i + 1])
        if not clean:
            continue
        clean_sequences += 1
        if any(attacks[i + 1:i + FUTURE_WINDOWS + 1]):
            clean_future_positive += 1

    fam_report = {}
    for family in DEV_FAMILIES:
        events = 0
        evaluable = 0
        candidate_total = 0
        for i in range(1, len(times)):
            if family not in famsets[i] or family in famsets[i - 1]:
                continue
            lo = i - HISTORY_WINDOWS
            if lo < 0 or any(attacks[lo:i]):
                continue
            events += 1
            candidates = 0
            for c in range(max(HISTORY_WINDOWS - 1, i - FUTURE_WINDOWS), i):
                if not eligible_cutoff(times, c):
                    continue
                hlo = c - HISTORY_WINDOWS + 1
                if any(attacks[hlo:c + 1]):
                    continue
                if any(family in famsets[k] for k in range(c + 1, min(len(times), c + FUTURE_WINDOWS + 1))):
                    candidates += 1
            candidate_total += candidates
            if candidates > 0:
                evaluable += 1
        fam_report[family] = {
            "clean_onset_events": int(events),
            "evaluable_events": int(evaluable),
            "candidate_windows": int(candidate_total),
        }

    return {
        "bins": int(len(times)),
        "span_minutes": float((times[-1] - times[0]) / 60.0),
        "usable_12min": bool((times[-1] - times[0]) >= (HISTORY_WINDOWS + FUTURE_WINDOWS) * WINDOW_SECONDS),
        "clean_history_sequences": int(clean_sequences),
        "clean_future_positive_sequences": int(clean_future_positive),
        "families": fam_report,
    }


def aggregate(scenarios_by_cap: dict[str, dict]) -> dict:
    out = {
        "scenario_n": len(scenarios_by_cap),
        "usable_12min_scenarios": 0,
        "clean_history_sequences": 0,
        "clean_future_positive_sequences": 0,
        "families": {f: {"clean_onset_events": 0, "evaluable_events": 0, "candidate_windows": 0} for f in DEV_FAMILIES},
    }
    for row in scenarios_by_cap.values():
        out["usable_12min_scenarios"] += int(row["usable_12min"])
        out["clean_history_sequences"] += int(row["clean_history_sequences"])
        out["clean_future_positive_sequences"] += int(row["clean_future_positive_sequences"])
        for f in DEV_FAMILIES:
            for key in ("clean_onset_events", "evaluable_events", "candidate_windows"):
                out["families"][f][key] += int(row["families"][f][key])
    return out


def main():
    report = {
        "schema": "krishna-v31-iot23-row-cap-support-audit-v1",
        "source": BASE_URL,
        "checkpoints": list(CHECKPOINTS),
        "development_families": list(DEV_FAMILIES),
        "audit_only": True,
        "model_training": False,
        "final_validation_scored": False,
        "scenarios": {},
    }

    loaded = 0
    for idx, sc in enumerate(scenarios(), 1):
        name = sc.rstrip("/")
        print(f"V31 LOAD {idx}: {name}", flush=True)
        try:
            snapshots, actual_rows = stream_snapshots(sc)
        except Exception as exc:
            report["scenarios"][name] = {"error": repr(exc)}
            print(f"V31 WARN {name}: {exc!r}", flush=True)
            continue
        loaded += 1
        entry = {"actual_rows_read": int(actual_rows), "checkpoints": {}}
        for cap in CHECKPOINTS:
            stats = analyze_bins(snapshots[cap])
            stats["requested_row_cap"] = int(cap)
            stats["actual_rows_available_up_to_cap"] = int(min(actual_rows, cap))
            entry["checkpoints"][str(cap)] = stats
        report["scenarios"][name] = entry
        print(json.dumps({name: entry}, indent=2), flush=True)

    if loaded < 8:
        raise RuntimeError(f"Only {loaded} IoT-23 scenarios loaded")

    per_cap = {}
    for cap in CHECKPOINTS:
        rows = {
            name: entry["checkpoints"][str(cap)]
            for name, entry in report["scenarios"].items()
            if "checkpoints" in entry
        }
        per_cap[str(cap)] = aggregate(rows)
    report["aggregate"] = per_cap

    a = per_cap[str(CHECKPOINTS[0])]
    b = per_cap[str(CHECKPOINTS[1])]
    deltas = {
        "usable_12min_scenarios": b["usable_12min_scenarios"] - a["usable_12min_scenarios"],
        "clean_history_sequences": b["clean_history_sequences"] - a["clean_history_sequences"],
        "clean_future_positive_sequences": b["clean_future_positive_sequences"] - a["clean_future_positive_sequences"],
        "families": {},
    }
    family_expanded = False
    for f in DEV_FAMILIES:
        fd = {
            key: b["families"][f][key] - a["families"][f][key]
            for key in ("clean_onset_events", "evaluable_events", "candidate_windows")
        }
        deltas["families"][f] = fd
        family_expanded = family_expanded or fd["evaluable_events"] > 0 or fd["candidate_windows"] > 0

    base_clean = max(1, a["clean_history_sequences"])
    clean_growth = (b["clean_history_sequences"] - a["clean_history_sequences"]) / base_clean
    recommend = bool(
        deltas["usable_12min_scenarios"] > 0
        or deltas["clean_future_positive_sequences"] > 0
        or family_expanded
        or clean_growth >= 0.10
    )
    report["delta_300k_minus_100k"] = deltas
    report["clean_history_growth_fraction"] = float(clean_growth)
    report["decision"] = {
        "recommend_expand_next_model_row_cap": recommend,
        "reason": (
            "300k materially expands protocol support; run the next development model on the larger cap."
            if recommend else
            "300k does not materially expand required support; keep the smaller cap and fix representation/calibration instead."
        ),
    }

    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary = {
        "aggregate": per_cap,
        "delta_300k_minus_100k": deltas,
        "clean_history_growth_fraction": clean_growth,
        "decision": report["decision"],
    }
    (OUT / "REPORT.md").write_text(
        "# V31 IoT-23 row-cap temporal-support audit\n\n"
        "Support-only audit; no model was trained and no forecasting performance claim is made.\n\n"
        "```json\n" + json.dumps(summary, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
