"""V114 development-only multi-domain PS-complete world-model recovery.

Motivation: V113 showed that a CICAPT-only frozen candidate remained outside support
on a fresh Internet botnet capture and failed the persistence gate. V114 does NOT use
V113 (or any consumed external one-shot bytes) for fitting, selection, normalization,
or thresholding. Instead it deliberately expands DEVELOPMENT coverage with a separate
raw-PCAP source, CTU-Malware-Capture-Botnet-350-1 (Mansabo), plus CICAPT-IIoT2024.

Contract:
- full 34-feature SIH flow+packet schema;
- GraphSAGE+LSTM residual world model, 8 history / 4 future 10-second windows;
- source-balanced train/validation from CICAPT Phase-1 + CTU-350-1;
- candidate selection uses development validation only;
- CICAPT Phase-2 is development sanity only and never used for candidate selection;
- support center/scale are fit on balanced training only; threshold on balanced
  validation only;
- all consumed one-shot captures remain quarantined.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .ps_complete import FEATURES, SCHEMA
from .support_gate import fit as fit_support_gate, score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, EMBARGO_SEQUENCES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    RecoveryContractError, file_hash, canonical_sha256, verify_development_capture,
    build_sequences, chronological_phase1_split, persistence_prediction, mse,
    infer_state,
)
from .v108_ps_complete_graph_recovery import train_seed
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs

CTU_DEV_DATASET = "CTU-Malware-Capture-Botnet-350-1"
CTU_DEV_CAPTURE = "2018-05-03_win16.pcap"

# Exact consumed external captures must never enter V114 fitting/selection.
QUARANTINED_SHA256 = {
    "v111_ctu3271": "cf478922f789926dab81f212a1a64d604b849068908c5c8885f42cdc32206ae3",
    "v113_ctu1111": "510e9bc5237b037e240c0064bcba3c073e2363abaecf6a20478c361f5f6ec613",
}
QUARANTINED_NAME_FRAGMENTS = (
    "hikari", "Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap".lower(),
    "capture_win11.pcap", "2015-03-09_capture-win10.pcap", "miuref.pcap",
)


def reject_quarantined(path: Path) -> str:
    lower = path.name.lower()
    if any(fragment in lower for fragment in QUARANTINED_NAME_FRAGMENTS):
        raise RecoveryContractError(f"Consumed external capture is quarantined from V114: {path.name}")
    observed = file_hash(path)
    if observed in QUARANTINED_SHA256.values():
        raise RecoveryContractError("Consumed external capture hash is quarantined from V114")
    return observed


def verify_ctu_development(path: Path) -> str:
    if path.name != CTU_DEV_CAPTURE:
        raise RecoveryContractError(f"Unexpected V114 CTU development capture: {path.name}")
    return reject_quarantined(path)


def split_generic(n: int):
    cut = int(n * 0.70)
    val_start = cut + EMBARGO_SEQUENCES
    if cut < 100 or n - val_start < 50:
        raise RecoveryContractError(
            f"Development source too small after embargo: sequences={n}, train={cut}, val={n-val_start}"
        )
    return np.arange(cut), np.arange(val_start, n)


def evenly_spaced(ids: np.ndarray, cap: int) -> np.ndarray:
    ids = np.asarray(ids, dtype=np.int64)
    if len(ids) <= cap:
        return ids
    pos = np.linspace(0, len(ids) - 1, num=cap, dtype=np.int64)
    return ids[pos]


def source_arrays(seq, ids):
    sx, sa, sm, sy, _ = seq
    return sx[ids], sa[ids], sm[ids], sy[ids]


def concat_arrays(*parts):
    return tuple(np.concatenate([p[i] for p in parts], axis=0) for i in range(4))


def source_metrics(model, arrays, batch_size: int):
    x, a, m, y = arrays
    pred = infer_state(model, x, a, m, batch_size=batch_size)
    persist = persistence_prediction(x, m)
    model_mse = mse(pred, y)
    persistence_mse = mse(persist, y)
    improvement = (persistence_mse - model_mse) / persistence_mse if persistence_mse else 0.0
    return {
        "sequences": int(len(x)),
        "model_mse": float(model_mse),
        "persistence_mse": float(persistence_mse),
        "improvement_vs_persistence": float(improvement),
        "beats_persistence": bool(model_mse < persistence_mse),
    }


def support_metrics(gate, arrays):
    x, _, m, _ = arrays
    scores = support_score(gate, x, m)
    threshold = float(gate["threshold"])
    supported = scores <= threshold
    return {
        "threshold": threshold,
        "supported_sequences": int(supported.sum()),
        "total_sequences": int(len(supported)),
        "supported_fraction": float(supported.mean()) if len(supported) else 0.0,
        "median_score": float(np.median(scores)) if len(scores) else None,
        "max_score": float(np.max(scores)) if len(scores) else None,
    }


def packet_presence(graph_x, graph_mask):
    idx = FEATURES.index("packet_features_present")
    vals = graph_x[:, :, idx][graph_mask > 0]
    return float(vals.mean()) if len(vals) else 0.0


def select_candidate(rows: dict[str, dict]) -> str:
    def objective(item):
        seed, row = item
        val = row["validation"]
        ratios = []
        for key in ("cicapt_phase1", "ctu350"):
            m = val[key]
            denom = max(float(m["persistence_mse"]), 1e-12)
            ratios.append(float(m["model_mse"]) / denom)
        all_dev_pass = all(val[k]["beats_persistence"] for k in ("cicapt_phase1", "ctu350"))
        return (0 if all_dev_pass else 1, max(ratios), sum(ratios), int(seed))
    return min(rows.items(), key=objective)[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cicapt-phase1", required=True, type=Path)
    ap.add_argument("--cicapt-phase2", required=True, type=Path)
    ap.add_argument("--ctu-dev", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--packet-limit-cicapt", type=int, default=900000)
    ap.add_argument("--packet-limit-ctu", type=int, default=900000)
    ap.add_argument("--max-train-per-source", type=int, default=2200)
    ap.add_argument("--max-valid-per-source", type=int, default=900)
    ap.add_argument("--seeds", nargs="+", type=int, default=[42,43,44])
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--batch-size", type=int, default=64)
    args = ap.parse_args()
    if len(set(args.seeds)) < 3:
        ap.error("At least three distinct development seeds are required")
    if len(FEATURES) != 34:
        raise RecoveryContractError(f"V114 requires the full 34-feature schema, got {len(FEATURES)}")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        ap.error("V114 output directory must be absent or empty")

    p1_sha = verify_development_capture(args.cicapt_phase1, PHASE1_NAME, PHASE1_SHA256)
    p2_sha = verify_development_capture(args.cicapt_phase2, PHASE2_NAME, PHASE2_SHA256)
    ctu_sha = verify_ctu_development(args.ctu_dev)

    print("V114 decoding CICAPT Phase-1", flush=True)
    t1, x1, a1, m1, n1, audit1 = tolerant_packet_service_graphs(args.cicapt_phase1, args.packet_limit_cicapt)
    print("V114 decoding CTU-350-1 development", flush=True)
    tc, xc, ac, mc, nc, auditc = tolerant_packet_service_graphs(args.ctu_dev, args.packet_limit_ctu)
    print("V114 decoding CICAPT Phase-2 sanity", flush=True)
    t2, x2, a2, m2, n2, audit2 = tolerant_packet_service_graphs(args.cicapt_phase2, args.packet_limit_cicapt)

    seq1 = build_sequences(t1, x1, a1, m1)
    seqc = build_sequences(tc, xc, ac, mc)
    seq2 = build_sequences(t2, x2, a2, m2)
    tr1, va1 = chronological_phase1_split(len(seq1[0]))
    trc, vac = split_generic(len(seqc[0]))

    tr1 = evenly_spaced(tr1, args.max_train_per_source)
    trc = evenly_spaced(trc, args.max_train_per_source)
    va1 = evenly_spaced(va1, args.max_valid_per_source)
    vac = evenly_spaced(vac, args.max_valid_per_source)
    # Source-balanced cardinality prevents either environment dominating fitting.
    train_cap = min(len(tr1), len(trc))
    valid_cap = min(len(va1), len(vac))
    tr1 = evenly_spaced(tr1, train_cap); trc = evenly_spaced(trc, train_cap)
    va1 = evenly_spaced(va1, valid_cap); vac = evenly_spaced(vac, valid_cap)

    train1 = source_arrays(seq1, tr1); trainc = source_arrays(seqc, trc)
    valid1 = source_arrays(seq1, va1); validc = source_arrays(seqc, vac)
    phase2 = source_arrays(seq2, np.arange(len(seq2[0])))
    train = concat_arrays(train1, trainc)
    valid = concat_arrays(valid1, validc)

    rows = {}; trained = {}; curves = {}
    for seed in args.seeds:
        print(f"V114 training seed={seed}", flush=True)
        model, best, epoch, curve = train_seed(train, valid, int(seed), args.epochs, args.batch_size)
        validation = {
            "cicapt_phase1": source_metrics(model, valid1, args.batch_size),
            "ctu350": source_metrics(model, validc, args.batch_size),
        }
        rows[str(seed)] = {
            "seed": int(seed), "selected_epoch": int(epoch),
            "combined_validation_mse": float(best), "validation": validation,
            "phase2_sanity": source_metrics(model, phase2, args.batch_size),
        }
        trained[str(seed)] = model; curves[str(seed)] = curve
        print(json.dumps(rows[str(seed)], indent=2), flush=True)

    selected_key = select_candidate(rows)
    selected = rows[selected_key]; model = trained[selected_key]

    gate = fit_support_gate(train[0], train[2], valid[0], valid[2])
    gate["fit_provenance"] = {
        "center_scale": "balanced CICAPT Phase-1 train + CTU-350-1 train only",
        "threshold": "balanced CICAPT Phase-1 validation + CTU-350-1 validation only",
        "cicapt_phase2_excluded_from_fit": True,
        "consumed_external_excluded_from_fit": True,
    }
    support = {
        "cicapt_phase1_validation": support_metrics(gate, valid1),
        "ctu350_validation": support_metrics(gate, validc),
        "cicapt_phase2_sanity": support_metrics(gate, phase2),
    }

    development_gates = {
        "cicapt_phase1_validation_beats_persistence": bool(selected["validation"]["cicapt_phase1"]["beats_persistence"]),
        "ctu350_validation_beats_persistence": bool(selected["validation"]["ctu350"]["beats_persistence"]),
        "cicapt_phase2_sanity_beats_persistence": bool(selected["phase2_sanity"]["beats_persistence"]),
        "cicapt_phase1_validation_support_at_least_0_95": support["cicapt_phase1_validation"]["supported_fraction"] >= 0.95,
        "ctu350_validation_support_at_least_0_95": support["ctu350_validation"]["supported_fraction"] >= 0.95,
        "cicapt_phase2_sanity_support_at_least_0_90": support["cicapt_phase2_sanity"]["supported_fraction"] >= 0.90,
        "cicapt_packet_presence_at_least_0_95": min(packet_presence(x1,m1), packet_presence(x2,m2)) >= 0.95,
        "ctu350_packet_presence_at_least_0_95": packet_presence(xc,mc) >= 0.95,
    }
    passed = all(development_gates.values())

    adapter = {
        "schema": SCHEMA, "features": list(FEATURES), "feature_count": len(FEATURES),
        "mode": "service", "window_seconds": WINDOW_SECONDS, "history_windows": HISTORY,
        "forecast_windows": HORIZON, "max_nodes": MAX_NODES, "packet_features_required": True,
        "mapping": "raw PCAP/PCAPNG -> V112 tolerant audited decoder -> bidirectional connections -> PS-complete service graph",
        "pcap_reader_mode": {"allow_truncated": True},
        "development_domains": ["CICAPT-IIoT2024", CTU_DEV_DATASET],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "gnn_lstm_multidomain_ps_complete_candidate.npz"
    gate_path = args.output_dir / "support_gate.json"
    meta = {
        "schema": SCHEMA, "features": list(FEATURES), "architecture": "gnn_lstm",
        "history": HISTORY, "horizon": HORIZON, "mode": "service", "max_nodes": MAX_NODES,
        "window_seconds": WINDOW_SECONDS, "decoder": "residual", "seed": int(selected_key),
        "trained": True, "packet_features_trained": True, "ps_complete_features_trained": True,
        "multi_domain_development": True, "risk_head_trained": False, "stage_supervised": False,
        "development_source_hashes": [p1_sha, p2_sha, ctu_sha],
        "consumed_external_used_for_fitting": False,
        "claim_boundary": "Development-only multi-domain state-transition recovery; no fresh external/stage/precompromise claim.",
    }
    model.save(model_path, meta)
    gate_path.write_text(json.dumps(gate, indent=2, allow_nan=False) + "\n")

    report = {
        "schema_version": "v114.1",
        "status": "DEV_MULTIDOMAIN_PASS" if passed else "DEV_MULTIDOMAIN_FAIL",
        "recovery_gate_passed": bool(passed),
        "claim_boundary": "Development-only multi-domain PS-complete recovery. V99/V102/V104/V106/V111/V113 one-shot data are excluded from fitting/selection; no new external generalisation claim is made.",
        "development_sources": {
            "cicapt_phase1": {"sha256": p1_sha, "decoded_ipv4_packets": int(n1), "observed_windows": int(len(t1)), "contiguous_sequences": int(len(seq1[0])), "parser_audit": audit1},
            "ctu350": {"dataset": CTU_DEV_DATASET, "capture": CTU_DEV_CAPTURE, "sha256": ctu_sha, "decoded_ipv4_packets": int(nc), "observed_windows": int(len(tc)), "contiguous_sequences": int(len(seqc[0])), "parser_audit": auditc},
            "cicapt_phase2_sanity": {"sha256": p2_sha, "decoded_ipv4_packets": int(n2), "observed_windows": int(len(t2)), "contiguous_sequences": int(len(seq2[0])), "parser_audit": audit2, "used_for_selection": False},
        },
        "balanced_sampling": {"train_sequences_per_source": int(train_cap), "validation_sequences_per_source": int(valid_cap), "embargo_sequences": EMBARGO_SEQUENCES},
        "selection": {"rule": "prefer seeds beating persistence on both selected development validation domains, then minimize worst source MSE/persistence ratio; CICAPT Phase-2 excluded", "selected_seed": int(selected_key), "phase2_used_for_selection": False, "consumed_external_used_for_selection": False},
        "seeds": rows, "selected_candidate": selected,
        "support_gate": {"method": gate["method"], "threshold": float(gate["threshold"]), "fit_provenance": gate["fit_provenance"], "evaluation": support},
        "packet_features_present_mean": {"cicapt_phase1": packet_presence(x1,m1), "ctu350": packet_presence(xc,mc), "cicapt_phase2": packet_presence(x2,m2)},
        "development_gates": development_gates,
        "adapter_contract": adapter, "adapter_contract_sha256": canonical_sha256(adapter),
        "freeze": {"model_file": model_path.name, "model_sha256": file_hash(model_path), "support_gate_file": gate_path.name, "support_gate_sha256": file_hash(gate_path), "candidate_frozen_before_new_external_holdout": bool(passed), "new_external_holdout_selected": False},
        "quarantine": {"v111_sha256": QUARANTINED_SHA256["v111_ctu3271"], "v113_sha256": QUARANTINED_SHA256["v113_ctu1111"], "consumed_external_used_for_fitting": False},
        "training_curves": curves,
    }
    (args.output_dir / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    (args.output_dir / "adapter_contract.json").write_text(json.dumps(adapter, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "selected_seed": int(selected_key), "selected_candidate": selected, "support": support}, indent=2))
    return 0 if passed else 2

if __name__ == "__main__":
    raise SystemExit(main())
