"""Prepare V45 10-second network graph datasets with explicit provenance.

Historical V8-V15 converters are left unchanged for reproducibility. This command
creates new V45 artifacts only. Packet captures never receive invented attack
labels: classic IDS2018 PCAP preparation preserves packet evidence and leaves
risk truth unknown until independent labels/timelines are attached for evaluation.

Examples:
  python -m garuda_v3.prepare_v45_data ids2018 flows.csv --output out.npz --campaign ids-day-1 --family DoS
  python -m garuda_v3.prepare_v45_data ids2018-pcap capture.pcap --output packet.npz --campaign ids-pcap-1 --family DoS
  python -m garuda_v3.prepare_v45_data cicapt capture.pcapng --output out.npz --campaign apt-phase-1
  python -m garuda_v3.prepare_v45_data ctu capture.binetflow --output ctu.npz --campaign ctu-5 --mode service
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .data import convert, save_dataset
from .multisource import ctu_graph, pcapng_graph
from .pcap import convert_pcap

WINDOW_SECONDS = 10


def prepare(args):
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("V45 prepared artifacts are immutable; choose a new output path")

    if args.kind == "ids2018":
        data = convert(args.input, mode=args.mode, window_seconds=WINDOW_SECONDS, max_nodes=args.max_nodes)
        data["metadata"].update(
            campaign_id=args.campaign,
            dataset_id="CIC-IDS-2018",
            attack_family=args.family or "unspecified",
            v45_role="forecast_development_or_holdout",
            evidence_type="completed-flow telemetry",
        )
    elif args.kind == "ids2018-pcap":
        data = convert_pcap(
            args.input,
            mode=args.mode,
            window_seconds=WINDOW_SECONDS,
            max_packets=args.max_packets,
            max_nodes=args.max_nodes,
            drop_last=True,
        )
        data["metadata"].update(
            campaign_id=args.campaign,
            dataset_id="CIC-IDS-2018",
            attack_family=args.family or "unspecified",
            v45_role="state_forecasting_network_evidence",
            evidence_type="raw packet telemetry",
            label_provenance="packet capture alone does not establish attack truth; all risk labels remain unknown",
            risk_labels_attached=False,
        )
    elif args.kind == "cicapt":
        data = pcapng_graph(
            args.input,
            args.campaign,
            mode=args.mode,
            window=WINDOW_SECONDS,
            max_nodes=args.max_nodes,
        )
        data["metadata"].update(
            attack_family=args.family or "CICAPT-campaign",
            v45_role="forecast_development_or_holdout",
            evidence_type="raw packet telemetry",
        )
    else:
        if args.mode != "service":
            raise ValueError("Current CTU adapter is service-graph only")
        data = ctu_graph(args.input, args.campaign, window=WINDOW_SECONDS)
        data["metadata"].update(
            attack_family=args.family or "CTU-13",
            v45_role="separate_evaluation_only",
            evidence_type="completed-flow telemetry",
        )

    data["metadata"].update(
        v45_contract="10-second-network-graph",
        runtime_evidence="network-only",
        unknown_label_semantics="unknown is never benign",
        verified_timeline_used_as_feature=False,
    )
    save_dataset(data, output)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["ids2018", "ids2018-pcap", "cicapt", "ctu"])
    parser.add_argument("input")
    parser.add_argument("--output", required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--family")
    parser.add_argument("--mode", choices=["host", "service"], default="host")
    parser.add_argument("--max-nodes", type=int, default=64)
    parser.add_argument("--max-packets", type=int, default=2_000_000,
                        help="bounded packet budget for classic IDS2018 PCAP input")
    args = parser.parse_args()
    if args.max_nodes < 32:
        parser.error("max-nodes must be at least 32")
    if args.max_packets < 1 or args.max_packets > 10_000_000:
        parser.error("max-packets must be 1..10000000")
    data = prepare(args)
    print(json.dumps({k: v for k, v in data["metadata"].items() if k != "node_names"}, indent=2))


if __name__ == "__main__":
    main()
