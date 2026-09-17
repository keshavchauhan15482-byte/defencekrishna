from __future__ import annotations

import json
import re
import urllib.request
from collections import Counter
from pathlib import Path

OUT = Path("artifacts/iot23_onset_audit")
OUT.mkdir(parents=True, exist_ok=True)
BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
MIN_CLEAN_HISTORY_SECONDS = 8 * 60
MAX_ROWS_PER_SCENARIO = 1_000_000


def scenarios():
    req = urllib.request.Request(BASE_URL, headers={"User-Agent": "KrishnaDefence-V23/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        html = r.read().decode("utf-8", errors="ignore")
    return sorted(set(re.findall(r'href="(CTU-IoT[^"]+/)"', html)))


def parse_label(field: str):
    parts = field.strip().split()
    if len(parts) < 3:
        return "unknown", "unknown"
    return parts[1].strip().lower(), parts[2].strip().lower()


def audit_scenario(sc: str) -> dict:
    url = f"{BASE_URL}{sc}bro/conn.log.labeled"
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V23/1.0"})
    total = benign = malicious = 0
    t_min = t_max = first_attack = None
    first_attack_label = None
    benign_before_first = 0
    last_benign_before_first = None
    attack_labels = Counter()
    srcs, dsts = set(), set()
    with urllib.request.urlopen(req, timeout=90) as r:
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
            label, detail = parse_label(p[-1])
            total += 1
            t_min = ts if t_min is None else min(t_min, ts)
            t_max = ts if t_max is None else max(t_max, ts)
            if len(srcs) < 20000:
                srcs.add(p[2])
            if len(dsts) < 20000:
                dsts.add(p[4])
            if label == "malicious":
                malicious += 1
                attack_labels[detail] += 1
                if first_attack is None:
                    first_attack = ts
                    first_attack_label = detail
            else:
                benign += 1
                if first_attack is None:
                    benign_before_first += 1
                    last_benign_before_first = ts
            if total >= MAX_ROWS_PER_SCENARIO:
                break
    if t_min is None:
        raise RuntimeError("no valid rows")
    clean_span = None if first_attack is None else max(0.0, first_attack - t_min)
    immediate_gap = None if first_attack is None or last_benign_before_first is None else max(0.0, first_attack - last_benign_before_first)
    return {
        "scenario": sc.rstrip("/"),
        "source_url": url,
        "rows_scanned": total,
        "benign_rows": benign,
        "malicious_rows": malicious,
        "capture_start_ts": t_min,
        "capture_end_ts": t_max,
        "capture_span_seconds": t_max - t_min,
        "first_attack_ts": first_attack,
        "first_attack_label": first_attack_label,
        "benign_rows_before_first_attack": benign_before_first,
        "clean_prehistory_seconds": clean_span,
        "last_benign_to_attack_gap_seconds": immediate_gap,
        "has_8min_clean_prehistory": bool(first_attack is not None and clean_span is not None and clean_span >= MIN_CLEAN_HISTORY_SECONDS and benign_before_first > 0),
        "attack_label_counts": dict(attack_labels),
        "source_ip_sample_unique": len(srcs),
        "destination_ip_sample_unique": len(dsts),
        "truncated_at_rows": total >= MAX_ROWS_PER_SCENARIO,
    }


def main():
    scs = scenarios()
    print(f"Found {len(scs)} official IoT-23 scenarios", flush=True)
    report = {
        "schema": "krishna-v23-iot23-onset-audit-v1",
        "source": BASE_URL,
        "strict_network_only": True,
        "minimum_clean_history_seconds": MIN_CLEAN_HISTORY_SECONDS,
        "scenarios": [],
    }
    for i, sc in enumerate(scs, 1):
        print(f"AUDIT {i}/{len(scs)} {sc}", flush=True)
        try:
            row = audit_scenario(sc)
            report["scenarios"].append(row)
            print(json.dumps({k: row[k] for k in ["scenario", "rows_scanned", "first_attack_label", "clean_prehistory_seconds", "has_8min_clean_prehistory"]}), flush=True)
        except Exception as e:
            report["scenarios"].append({"scenario": sc.rstrip("/"), "error": repr(e)})
            print(f"WARN {sc}: {e!r}", flush=True)
    eligible = [x for x in report["scenarios"] if x.get("has_8min_clean_prehistory")]
    labels = Counter(x.get("first_attack_label") for x in eligible if x.get("first_attack_label"))
    report["eligible_clean_onset_scenarios"] = [x["scenario"] for x in eligible]
    report["eligible_count"] = len(eligible)
    report["eligible_first_attack_label_counts"] = dict(labels)
    report["ready_for_clean_onset_experiment"] = len(eligible) >= 3
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = [
        "# IoT-23 clean-onset audit",
        "",
        f"Official scenarios discovered: **{len(scs)}**",
        f"Scenarios with >=8 minutes clean prehistory before first malicious flow: **{len(eligible)}**",
        f"Ready for clean-onset experiment: **{report['ready_for_clean_onset_experiment']}**",
        "",
        "```json",
        json.dumps({"eligible": [{k: x.get(k) for k in ["scenario", "first_attack_label", "clean_prehistory_seconds", "attack_label_counts"]} for x in eligible]}, indent=2),
        "```",
    ]
    (OUT / "REPORT.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"eligible_count": len(eligible), "labels": dict(labels)}, indent=2), flush=True)
    if len(eligible) < 3:
        raise RuntimeError(f"IoT-23 has only {len(eligible)} scenarios with >=8min clean prehistory")


if __name__ == "__main__":
    main()
