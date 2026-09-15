"""
NTRO SIH26153: Enterprise PCAP / PCAPNG Packet Telemetry Ingestion Pipeline
Uses Scapy to extract raw packet headers, inter-arrival times, TCP flags, TTL metrics,
and port entropy into canonical 12-dimensional World Model state vectors S_t.
"""

import math
import os
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP

class ScapyPCAPFeatureExtractor:
    def __init__(self, window_sec=10):
        self.window_sec = window_sec

    def _compute_entropy(self, ports):
        if not ports:
            return 0.1
        n = len(ports)
        if n < 5:
            return 0.2
        counts = {}
        for p in ports:
            counts[p] = counts.get(p, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return min(3.5, entropy)

    def extract_windows_from_pcap(self, pcap_filepath, max_windows=100):
        """
        Parses PCAP file into continuous temporal observation windows S_t.
        """
        if not os.path.exists(pcap_filepath):
            raise FileNotFoundError(f"PCAP file not found: {pcap_filepath}")

        packets = rdpcap(pcap_filepath)
        if not packets:
            raise ValueError(f"Empty PCAP capture: {pcap_filepath}")

        first_ts = float(packets[0].time)
        win_data = defaultdict(lambda: {
            "syn": 0, "ack": 0, "rst": 0, "fin": 0,
            "pkts": 0, "bytes": 0, "iat_list": [], "ttls": [],
            "win_sizes": [], "ports": [], "last_time": None
        })

        for pkt in packets:
            if IP in pkt:
                ts = float(pkt.time) - first_ts
                win_idx = int(ts // self.window_sec)
                w = win_data[win_idx]

                w["pkts"] += 1
                w["bytes"] += len(pkt)
                w["ttls"].append(pkt[IP].ttl)

                if w["last_time"] is not None:
                    iat_ms = (ts - w["last_time"]) * 1000.0
                    w["iat_list"].append(iat_ms)
                w["last_time"] = ts

                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if flags & 0x02: # SYN
                        w["syn"] += 1
                    if flags & 0x10: # ACK
                        w["ack"] += 1
                    if flags & 0x04: # RST
                        w["rst"] += 1
                    if flags & 0x01: # FIN
                        w["fin"] += 1
                    w["win_sizes"].append(pkt[TCP].window)
                    w["ports"].append(pkt[TCP].dport)
                elif UDP in pkt:
                    w["ports"].append(pkt[UDP].dport)

        windows = []
        sorted_keys = sorted(win_data.keys())

        for win_idx in sorted_keys[:max_windows]:
            w = win_data[win_idx]
            tot_syn = w["syn"]
            tot_ack = max(1, w["ack"])
            tot_rst_fin = w["rst"] + w["fin"]
            tot_pkts = max(1, w["pkts"])
            tot_bytes = w["bytes"]

            iats = w["iat_list"] if w["iat_list"] else [50.0]
            mean_iat = sum(iats) / len(iats)
            var_iat = sum((x - mean_iat) ** 2 for x in iats) / len(iats)

            ttls = w["ttls"] if w["ttls"] else [64]
            mean_ttl = sum(ttls) / len(ttls)
            var_ttl = sum((x - mean_ttl) ** 2 for x in ttls) / len(ttls)

            wins = w["win_sizes"] if w["win_sizes"] else [64240]
            mean_win = sum(wins) / len(wins)

            port_entropy = self._compute_entropy(w["ports"][:100])

            syn_ack_ratio = min(1.0, (tot_syn / tot_ack) / 2.0)
            fin_rst_ratio = min(1.0, tot_rst_fin / tot_pkts)
            iat_mean_norm = min(1.0, mean_iat / 100.0)
            iat_var_norm = min(1.0, var_iat / 20000.0)
            bytes_flow_norm = min(1.0, tot_bytes / 50000.0)
            pkts_flow_norm = min(1.0, tot_pkts / 200.0)
            ttl_mean_norm = min(1.0, mean_ttl / 128.0)
            ttl_var_norm = min(1.0, var_ttl / 10.0)
            tcp_win_norm = min(1.0, mean_win / 65535.0)
            port_entropy_norm = min(1.0, port_entropy / 3.5)
            fragment_norm = 0.0
            retransmission_norm = min(1.0, (tot_rst_fin / tot_pkts) * 0.5)

            vec = [
                syn_ack_ratio, fin_rst_ratio, iat_mean_norm, iat_var_norm,
                bytes_flow_norm, pkts_flow_norm, ttl_mean_norm, ttl_var_norm,
                tcp_win_norm, port_entropy_norm, fragment_norm, retransmission_norm
            ]

            windows.append({
                "time_window": win_idx * self.window_sec,
                "state_vector": [round(v, 4) for v in vec],
                "packet_count": tot_pkts,
                "bytes": tot_bytes,
                "port_entropy": round(port_entropy, 2)
            })

        return windows

if __name__ == "__main__":
    extractor = ScapyPCAPFeatureExtractor()
    print("✅ Scapy PCAP Feature Extractor initialized successfully.")
