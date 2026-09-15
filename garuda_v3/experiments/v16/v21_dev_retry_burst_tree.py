"""V21 development gate: generic retry/burst-aware unseen-family forecasting.

This keeps the frozen unseen-family protocol and the V20 30-second / 8-minute
history / 4-minute future horizon, but restores generic network-only signals that
are important for low-and-slow retry attacks without using attack-family names:

* hashed destination-port occupancy
* repeated destination / port / destination-port concentration
* source-flow inter-arrival timing
* flow burst / fan-out ratios

Final-validation families remain unscored. No family-specific feature or label is
used by the model.
"""
from pathlib import Path
import json

import numpy as np
import pandas as pd

import v19_dev_highres_tree as v19

PORT_BUCKETS = 32


def _safe_ratio(num, den):
    den = den.astype(float).replace(0.0, np.nan)
    return (num.astype(float) / den).fillna(0.0)


def build_state(df, dt, y, family_col, binary_col, date_col, ts_col):
    base = v19.base
    src_col = base.pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    dst_col = base.pick_col(df.columns, ["Des_IP", "Dst_IP", "Destination_IP", "dst_ip"])
    dport_col = base.pick_col(df.columns, ["Des_port", "Dst_port", "Destination_port", "dst_port"])
    proto_col = base.pick_col(df.columns, ["Protocol", "Proto"])
    service_col = base.pick_col(df.columns, ["Service", "Serv"])

    excluded = {x for x in [family_col, binary_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if base.norm(c) in {"class1", "class2", "class3"})
    numeric, _audit = base.strict_network_features(df, excluded)

    f = pd.DataFrame({
        "dt": dt,
        "y": y,
        "family": df[family_col].astype(str).map(base.norm_label),
        "src": df[src_col].astype(str) if src_col else "GLOBAL",
    })
    if dst_col:
        f["dst"] = df[dst_col].astype(str)
    if dport_col:
        f["dport"] = df[dport_col].fillna("__missing__").astype(str)
    for c in numeric:
        f[c] = base.numericize(df[c])

    cats = []
    for prefix, col, buckets in (
        ("proto", proto_col, v19.HASH_BUCKETS),
        ("service", service_col, v19.HASH_BUCKETS),
        ("dport", dport_col, PORT_BUCKETS),
    ):
        if col:
            values = df[col].fillna("__missing__").astype(str)
            b = values.map(lambda x: v19.bucket(x) if buckets == v19.HASH_BUCKETS else int.from_bytes(__import__("hashlib").blake2b(str(x).strip().lower().encode("utf-8", errors="ignore"), digest_size=4).digest(), "big") % buckets).to_numpy()
            for k in range(buckets):
                name = f"{prefix}_b{k}"
                f[name] = (b == k).astype(np.float32)
                cats.append(name)

    f = f.dropna(subset=["dt", "y"]).copy()
    f = f.sort_values(["src", "dt"]).reset_index(drop=True)
    f["bin"] = f["dt"].dt.floor(f"{v19.WINDOW_SECONDS}s")
    f["y"] = f["y"].astype(int)

    # Generic temporal retry/burst signal.  The first event for each source has no
    # prior inter-arrival and is left NaN so group statistics remain unbiased.
    f["interarrival_ms"] = f.groupby("src", sort=False)["dt"].diff().dt.total_seconds() * 1000.0

    g = f.groupby(["src", "bin"], sort=True)
    s = g[numeric].agg(["mean", "std", "max"])
    s.columns = ["__".join(x) for x in s.columns]
    if cats:
        s = s.join(g[cats].mean())

    s["flow_count"] = g.size().astype(float)
    s["attack_now"] = g["y"].max().astype(int)
    s["family_now"] = g["family"].agg(
        lambda x: tuple(sorted({base.norm_label(v) for v in x if base.norm_label(v) != "normal"}))
    )

    ia = g["interarrival_ms"].agg(["mean", "std", "min", "max"])
    ia.columns = [f"interarrival_ms__{c}" for c in ia.columns]
    s = s.join(ia)

    if dst_col:
        s["unique_dst"] = g["dst"].nunique().astype(float)
        max_same_dst = f.groupby(["src", "bin", "dst"], sort=False).size().groupby(level=[0, 1]).max().astype(float)
        s["max_same_dst"] = max_same_dst
        s["top_dst_fraction"] = _safe_ratio(s["max_same_dst"], s["flow_count"])
        s["dst_repeat_fraction"] = (1.0 - _safe_ratio(s["unique_dst"], s["flow_count"])).clip(0.0, 1.0)

    if dport_col:
        s["unique_dst_port"] = g["dport"].nunique().astype(float)
        max_same_port = f.groupby(["src", "bin", "dport"], sort=False).size().groupby(level=[0, 1]).max().astype(float)
        s["max_same_dst_port_value"] = max_same_port
        s["top_port_fraction"] = _safe_ratio(s["max_same_dst_port_value"], s["flow_count"])
        s["port_repeat_fraction"] = (1.0 - _safe_ratio(s["unique_dst_port"], s["flow_count"])).clip(0.0, 1.0)

    if dst_col and dport_col:
        pair_counts = f.groupby(["src", "bin", "dst", "dport"], sort=False).size()
        max_same_pair = pair_counts.groupby(level=[0, 1]).max().astype(float)
        unique_pairs = pair_counts.groupby(level=[0, 1]).size().astype(float)
        s["max_same_dst_port_pair"] = max_same_pair
        s["unique_dst_port_pairs"] = unique_pairs
        s["top_dst_port_pair_fraction"] = _safe_ratio(s["max_same_dst_port_pair"], s["flow_count"])
        s["dst_port_pair_repeat_fraction"] = (1.0 - _safe_ratio(s["unique_dst_port_pairs"], s["flow_count"])).clip(0.0, 1.0)

    s = s.reset_index().sort_values(["src", "bin"]).reset_index(drop=True)
    fcols = [c for c in s.columns if c not in ["src", "bin", "attack_now", "family_now"]]
    return s, fcols, numeric, cats, {
        "source_ip": src_col,
        "destination_ip": dst_col,
        "destination_port": dport_col,
        "protocol": proto_col,
        "service": service_col,
        "generic_retry_burst_features": True,
    }


def main():
    # Keep exactly the V20 temporal setup; only feature representation changes.
    v19.WINDOW_SECONDS = 30
    v19.HISTORY_WINDOWS = 16
    v19.FUTURE_WINDOWS = 8
    v19.OUT = Path("artifacts/v21_dev")
    v19.OUT.mkdir(parents=True, exist_ok=True)
    v19.build_state = build_state
    v19.main()

    # Rewrite metadata only; measured metrics remain exactly those emitted by v19.main.
    results_path = v19.OUT / "results.json"
    report = json.loads(results_path.read_text())
    report["schema"] = "krishna-v21-dev-retry-burst-tree-v1"
    report["purpose"] = "Development only; generic network-only retry/burst features; frozen final families not scored."
    report["window_seconds"] = 30
    report["generic_retry_burst_features"] = [
        "destination_port_hash_occupancy",
        "destination_concentration",
        "destination_port_concentration",
        "destination_port_pair_concentration",
        "source_interarrival_timing",
    ]
    results_path.write_text(json.dumps(report, indent=2))
    (v19.OUT / "REPORT.md").write_text(
        "# V21 retry/burst-aware unseen-family development\n\n"
        "Strict network-only generic features; frozen final families remain unscored.\n\n"
        "```json\n" + json.dumps({
            "chosen_policy_budget": report.get("chosen_policy_budget"),
            "macro_mean": report.get("macro_mean"),
            "development_target": report.get("development_target"),
        }, indent=2) + "\n```\n"
    )


if __name__ == "__main__":
    main()
