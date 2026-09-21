"""V92 corrected CICAPT attack-step onset lead-time audit.

V72 used the timestamp of the START of the final observed 10-second bucket as the
warning timestamp. A predictor consuming that bucket cannot issue its forecast until
the bucket ends, so V92 defines prediction_issue_epoch = cutoff_bucket_start +
WINDOW_SECONDS. This removes a deterministic 10-second lead-time inflation.

The recovered timeline is explicitly publisher_verified=false and contains no verified
incident IDs or compromise timestamps. Rows sharing an exact timestamp are grouped only
as one attack-step onset timestamp. V92 does not call these groups independent incidents
and does not claim verified successful-compromise/pre-compromise lead time.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np

from .v60_residual_state_forecasting import train_residual_world_model
from .v70_cicapt_packet_world_model import (
    EMBARGO_SEQUENCES,
    WINDOW_SECONDS,
    contiguous_sequences,
    packet_states,
)
from .v72_cicapt_attack_step_leadtime import (
    LOOKBACK_SECONDS,
    POLICY_FALSE_ALERT_BUDGET,
    load_events,
    sha256,
    transition_score,
    upper_tail_threshold,
)

PROTOCOL_VERSION = "V92-history-end-attack-step-onset-v1"
BOOTSTRAP_MIN_ONSETS = 20
BOOTSTRAP_ITERATIONS = 2000
BOOTSTRAP_SEED = 92026


def prediction_issue_times(cutoff_bucket_starts, window_seconds: int = WINDOW_SECONDS):
    """Earliest valid issue time after the complete observed history is available."""
    x = np.asarray(cutoff_bucket_starts, dtype=float)
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    return x + float(window_seconds)


def group_event_onsets(events):
    """Collapse only exact-timestamp duplicate/parallel timeline rows."""
    grouped = {}
    for row in events:
        epoch = float(row["epoch"])
        slot = grouped.setdefault(
            epoch, {"epoch": epoch, "tactics": set(), "techniques": set(), "raw_rows": 0}
        )
        slot["tactics"].add(str(row.get("tactic", "")).strip())
        slot["techniques"].add(str(row.get("technique", "")).strip())
        slot["raw_rows"] += 1
    out = []
    for epoch in sorted(grouped):
        slot = grouped[epoch]
        out.append({
            "epoch": float(epoch),
            "tactics": sorted(x for x in slot["tactics"] if x),
            "techniques": sorted(x for x in slot["techniques"] if x),
            "raw_rows": int(slot["raw_rows"]),
        })
    return out


def onset_audit(onsets, prediction_issue_epochs, lookback_seconds: int = LOOKBACK_SECONDS):
    """Count at most one warning hit per exact-timestamp onset group."""
    issue = np.sort(np.asarray(prediction_issue_epochs, dtype=float))
    rows, leads = [], []
    for onset in onsets:
        epoch = float(onset["epoch"])
        lo = epoch - float(lookback_seconds)
        eligible = issue[(issue >= lo) & (issue < epoch)]
        first = float(eligible[0]) if len(eligible) else None
        lead = float(epoch - first) if first is not None else None
        if lead is not None:
            leads.append(lead)
        rows.append({
            **onset,
            "warning_hit": bool(len(eligible)),
            "first_prediction_issue_epoch": first,
            "lead_seconds": lead,
            "qualifying_alert_windows": int(len(eligible)),
        })
    return rows, leads


def bootstrap_median_ci(
    leads,
    *,
    min_onsets: int = BOOTSTRAP_MIN_ONSETS,
    iterations: int = BOOTSTRAP_ITERATIONS,
    seed: int = BOOTSTRAP_SEED,
):
    """Deterministic percentile bootstrap over onset groups, or explicitly withhold."""
    x = np.asarray(leads, dtype=float)
    if len(x) < min_onsets:
        return {
            "withheld": True,
            "reason": f"fewer than {min_onsets} warned onset groups",
            "support": int(len(x)),
            "method": "percentile bootstrap over exact-timestamp onset groups",
        }
    if iterations < 200:
        raise ValueError("iterations must be at least 200")
    rng = np.random.default_rng(int(seed))
    med = np.empty(iterations, dtype=float)
    for i in range(iterations):
        med[i] = float(np.median(rng.choice(x, size=len(x), replace=True)))
    return {
        "withheld": False,
        "support": int(len(x)),
        "method": "percentile bootstrap over exact-timestamp onset groups",
        "iterations": int(iterations),
        "seed": int(seed),
        "median_seconds": float(np.median(x)),
        "ci95_seconds": [float(np.quantile(med, 0.025)), float(np.quantile(med, 0.975))],
    }


def lead_summary(leads):
    x = np.asarray(leads, dtype=float)
    return {
        "count": int(len(x)),
        "mean": float(np.mean(x)) if len(x) else None,
        "median": float(np.median(x)) if len(x) else None,
        "min": float(np.min(x)) if len(x) else None,
        "max": float(np.max(x)) if len(x) else None,
        "median_ci95": bootstrap_median_ci(x),
    }


def capture_catalogue_contract(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    source = data.get("sources", {}).get("cicapt_network", {})
    members = {m.get("name"): m for m in source.get("members", []) if isinstance(m, dict)}
    required = ("1stPhase-timed-Merged.pcap", "2ndPhase-timed-MergedV2.pcap")
    if any(name not in members for name in required):
        raise RuntimeError("CICAPT capture members are not pinned in catalogue")
    return {
        "catalogue_schema": data.get("schema"),
        "archive_sha256": source.get("sha256"),
        "mirror": source.get("mirror"),
        "version": source.get("version"),
        "official_source": source.get("official_source"),
        "license_status": source.get("license_status"),
        "members": {
            name: {"bytes": members[name].get("bytes"), "sha256": members[name].get("sha256")}
            for name in required
        },
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase1", required=True)
    p.add_argument("--phase2", required=True)
    p.add_argument("--timeline", required=True)
    p.add_argument("--timeline-provenance", required=True)
    p.add_argument("--catalogue", default="datasets/multisource/catalogue.json")
    p.add_argument("--output", required=True)
    p.add_argument("--packet-limit", type=int, default=3_000_000)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    prov_path = Path(args.timeline_provenance)
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    if prov.get("publisher_verified") is not False:
        raise RuntimeError("V92 expects explicitly non-publisher-verified timeline provenance")
    timeline_path = Path(args.timeline)
    expected = prov.get("sha256") or prov.get("source_sha256")
    timeline_sha = sha256(timeline_path)
    if expected and str(expected).lower() != timeline_sha.lower():
        raise RuntimeError(f"Timeline SHA mismatch {timeline_sha} != {expected}")

    capture_contract = capture_catalogue_contract(Path(args.catalogue))
    t1, s1, n1 = packet_states(Path(args.phase1), args.packet_limit)
    t2, s2, n2 = packet_states(Path(args.phase2), args.packet_limit)
    x1, f1, _c1 = contiguous_sequences(t1, s1)
    x2, f2, c2 = contiguous_sequences(t2, s2)

    n = len(x1)
    b1 = int(n * 0.60)
    b2 = int(n * 0.80)
    val_start = b1 + EMBARGO_SEQUENCES
    policy_start = b2 + EMBARGO_SEQUENCES
    val_end = max(val_start, b2 - EMBARGO_SEQUENCES)
    if b1 < 100 or val_end - val_start < 50 or n - policy_start < 50:
        raise RuntimeError(
            f"Insufficient Phase1 support n={n} train={b1} val={val_end-val_start} policy={n-policy_start}"
        )

    X = np.concatenate([x1, x2], axis=0)
    F = np.concatenate([f1, f2], axis=0)
    train = np.zeros(len(X), dtype=bool)
    val = np.zeros(len(X), dtype=bool)
    policy = np.zeros(len(X), dtype=bool)
    phase2 = np.zeros(len(X), dtype=bool)
    train[:b1] = True
    val[val_start:val_end] = True
    policy[policy_start:n] = True
    phase2[n:] = True

    raw_events = load_events(timeline_path, float(t2[0]), float(t2[-1]))
    onsets = group_event_onsets(raw_events)
    if len(onsets) < 5:
        raise RuntimeError(f"Too few timestamped onset groups within capture prefix: {len(onsets)}")

    rows = {}
    for seed in args.seeds:
        print(f"V92 seed={seed}", flush=True)
        world = train_residual_world_model(X, F, train, val, int(seed), epochs=args.epochs)
        score = transition_score(world["pred"], world["persistence"])
        threshold = upper_tail_threshold(score[policy], POLICY_FALSE_ALERT_BUDGET)
        policy_alert = score[policy] > threshold
        p2_ids = np.where(phase2)[0]
        p2_alert = score[p2_ids] > threshold

        legacy_cutoff_start = np.asarray(c2[p2_alert], dtype=float)
        issue_times = prediction_issue_times(legacy_cutoff_start)
        corrected_events, corrected_leads = onset_audit(onsets, issue_times)
        legacy_events, legacy_leads = onset_audit(onsets, legacy_cutoff_start)
        hits = sum(int(e["warning_hit"]) for e in corrected_events)
        legacy_hits = sum(int(e["warning_hit"]) for e in legacy_events)

        rows[str(seed)] = {
            "seed": int(seed),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "validation_mse": float(world["validation_mse"]),
            "validation_persistence_mse": float(world["validation_persistence_mse"]),
            "validation_state_gate_passed": bool(world["state_gate_passed"]),
            "threshold": float(threshold),
            "phase1_policy_sequences": int(policy.sum()),
            "phase1_policy_alerts": int(policy_alert.sum()),
            "phase1_policy_alert_rate": float(policy_alert.mean()),
            "phase2_sequences": int(len(p2_ids)),
            "phase2_alerts": int(p2_alert.sum()),
            "phase2_alert_rate": float(p2_alert.mean()),
            "onset_groups_evaluated": int(len(corrected_events)),
            "warning_hits": int(hits),
            "onset_group_warning_recall": float(hits / len(corrected_events)),
            "lead_seconds": lead_summary(corrected_leads),
            "onsets": corrected_events,
            "legacy_timestamp_diagnostic_only": {
                "warning_hits": int(legacy_hits),
                "onset_group_warning_recall": float(legacy_hits / len(legacy_events)),
                "lead_seconds": lead_summary(legacy_leads),
                "systematic_issue_timestamp_shift_seconds": int(WINDOW_SECONDS),
                "claim_eligible": False,
            },
        }

    vals = list(rows.values())
    recall = np.asarray([r["onset_group_warning_recall"] for r in vals], dtype=float)
    rates = np.asarray([r["phase2_alert_rate"] for r in vals], dtype=float)
    med = np.asarray([
        r["lead_seconds"]["median"] for r in vals if r["lead_seconds"]["median"] is not None
    ], dtype=float)
    legacy_med = np.asarray([
        r["legacy_timestamp_diagnostic_only"]["lead_seconds"]["median"]
        for r in vals
        if r["legacy_timestamp_diagnostic_only"]["lead_seconds"]["median"] is not None
    ], dtype=float)

    report = {
        "protocol_version": PROTOCOL_VERSION,
        "protocol": "Prospective prediction-only transition alert before third-party timestamped CICAPT attack-step onset groups",
        "git_commit": os.environ.get("GITHUB_SHA"),
        "claim_boundary": (
            "ATTACK-STEP ONSET timing diagnostic only. The timeline is a commit-pinned third-party copy with "
            "publisher_verified=false and has no verified incident or compromise identifiers. Prediction issue "
            "time is the END of the final observed window. This is NOT verified successful-compromise lead time, "
            "NOT verified pre-compromise proof, and NOT production zero-day prevention evidence."
        ),
        "compromise_claim_allowed": False,
        "incident_level_claim_allowed": False,
        "score_definition": "mean absolute predicted future-state transition away from persistence; prediction only",
        "policy_false_alert_budget": POLICY_FALSE_ALERT_BUDGET,
        "lookback_seconds": LOOKBACK_SECONDS,
        "timing_contract": {
            "window_seconds": int(WINDOW_SECONDS),
            "contiguous_sequence_cutoff_semantics": "start of final observed bucket",
            "prediction_issue_epoch": "cutoff_bucket_start + window_seconds",
            "legacy_timestamp_inflation_seconds": int(WINDOW_SECONDS),
            "onset_deduplication": "exact epoch only; no synthetic incident clustering",
            "late_or_at_onset_alert_counts_as_early": False,
        },
        "timeline": str(timeline_path),
        "timeline_sha256": timeline_sha,
        "timeline_provenance_sha256": sha256(prov_path),
        "timeline_source_tier": prov.get("source_tier"),
        "publisher_verified": prov.get("publisher_verified"),
        "capture_source_contract": capture_contract,
        "raw_timeline_rows_evaluated": int(len(raw_events)),
        "exact_timestamp_onset_groups_evaluated": int(len(onsets)),
        "phase1": {
            "decoded_packets": n1,
            "observed_windows": len(s1),
            "sequences": len(x1),
            "train": int(train.sum()),
            "validation": int(val.sum()),
            "policy": int(policy.sum()),
        },
        "phase2": {
            "decoded_packets": n2,
            "observed_windows": len(s2),
            "sequences": len(x2),
            "first_epoch": int(t2[0]),
            "last_epoch": int(t2[-1]),
        },
        "leakage_contract": {
            "phase2_used_for_training": False,
            "phase2_used_for_normalization": False,
            "phase2_used_for_blend_selection": False,
            "phase2_used_for_threshold_selection": False,
            "timeline_events_used_for_threshold_selection": False,
            "alert_score_uses_observed_future_ground_truth": False,
        },
        "seeds": rows,
        "summary": {
            "seed_evaluations": int(len(vals)),
            "onset_group_warning_recall_mean": float(recall.mean()),
            "onset_group_warning_recall_sd": float(recall.std(ddof=1)),
            "phase2_alert_rate_mean": float(rates.mean()),
            "phase2_alert_rate_sd": float(rates.std(ddof=1)),
            "corrected_median_attack_step_lead_seconds_mean_across_seeds": float(med.mean()) if len(med) else None,
            "legacy_start_timestamp_median_lead_seconds_mean_across_seeds_diagnostic_only": float(legacy_med.mean()) if len(legacy_med) else None,
            "all_validation_state_gates_pass": all(r["validation_state_gate_passed"] for r in vals),
        },
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2), flush=True)
    for seed, row in rows.items():
        print(seed, json.dumps({
            "phase1_policy_alert_rate": row["phase1_policy_alert_rate"],
            "phase2_alert_rate": row["phase2_alert_rate"],
            "onset_group_warning_recall": row["onset_group_warning_recall"],
            "lead_seconds": row["lead_seconds"],
        }, indent=2), flush=True)


if __name__ == "__main__":
    main()
