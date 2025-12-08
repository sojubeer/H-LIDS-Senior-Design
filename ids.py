#!/usr/bin/env python3
# ids.py — Lightweight Live IDS (Scapy + Pandas + RandomForest optional)
# Usage:
#   sudo -E python3 ids.py --iface any --window 2.0 --model model.pkl --threshold 0.6
#
# If model.pkl is missing, the classifier uses a simple heuristic rule.

import argparse
import os
import sys
import time
import threading
import queue
from datetime import datetime

# Packet capture
from scapy.all import AsyncSniffer, TCP, IP

# Data utilities
import pandas as pd
import numpy as np

# ML (optional)
from sklearn.ensemble import RandomForestClassifier
import joblib

# ---------------------------
# Classes (design-aligned)
# ---------------------------


class PacketAnalyzer:
    def __init__(self, iface: str, pkt_queue: queue.Queue):
        self.iface = iface
        self.pkt_queue = pkt_queue
        self.sniffer = None

    def _on_packet(self, pkt):
        try:
            ts = time.time()
            length = len(pkt)
            proto = "OTHER"
            src_ip, dst_ip, sport, dport, syn, ack = "", "", None, None, 0, 0

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

            if TCP in pkt:
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                syn = 1 if pkt[TCP].flags & 0x02 else 0  # SYN flag bit
                ack = 1 if pkt[TCP].flags & 0x10 else 0  # ACK flag bit
            else:
                # simple coarse protocol flag
                # (extend to UDP if you’d like)
                proto = proto

            self.pkt_queue.put(
                (ts, proto, src_ip, dst_ip, sport, dport, length, syn, ack)
            )
        except Exception:
            # swallow malformed packets
            pass

    def start(self):
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self._on_packet, store=False)
        self.sniffer.start()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None


class DataProcessor:
    def __init__(self, features_csv="features.csv"):
        self.features_csv = features_csv
        # initialize file with header if not exists
        if not os.path.exists(self.features_csv):
            pd.DataFrame(
                columns=[
                    "window_start",
                    "window_end",
                    "num_packets",
                    "pkts_per_sec",
                    "unique_dst_ports",
                    "avg_len",
                    "tcp_ratio",
                    "syn_ratio",
                ]
            ).to_csv(self.features_csv, index=False)

    def compute_features(self, rows, window_start, window_end):
        if not rows:
            return {
                "window_start": window_start,
                "window_end": window_end,
                "num_packets": 0,
                "pkts_per_sec": 0.0,
                "unique_dst_ports": 0,
                "avg_len": 0.0,
                "tcp_ratio": 0.0,
                "syn_ratio": 0.0,
            }

        df = pd.DataFrame(
            rows,
            columns=[
                "ts",
                "proto",
                "src",
                "dst",
                "sport",
                "dport",
                "length",
                "syn",
                "ack",
            ],
        )
        duration = max(1e-6, window_end - window_start)
        num_packets = len(df)
        pkts_per_sec = num_packets / duration

        tcp_df = df[df["proto"] == "TCP"]
        tcp_ratio = 0.0 if num_packets == 0 else len(tcp_df) / num_packets
        syn_ratio = 0.0 if len(tcp_df) == 0 else tcp_df["syn"].sum() / len(tcp_df)

        unique_dst_ports = int(tcp_df["dport"].nunique()) if "dport" in tcp_df else 0
        avg_len = float(df["length"].mean()) if "length" in df else 0.0

        feats = {
            "window_start": window_start,
            "window_end": window_end,
            "num_packets": int(num_packets),
            "pkts_per_sec": float(pkts_per_sec),
            "unique_dst_ports": int(unique_dst_ports),
            "avg_len": float(avg_len),
            "tcp_ratio": float(tcp_ratio),
            "syn_ratio": float(syn_ratio),
        }

        # append to CSV
        pd.DataFrame([feats]).to_csv(
            self.features_csv, mode="a", index=False, header=False
        )
        return feats


class MLClassifier:
    def __init__(self, model_path=None, threshold=0.6):
        self.model = None
        self.threshold = float(threshold)
        self.using_model = False
        if model_path and os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.using_model = True
            except Exception:
                self.model = None
                self.using_model = False

    def predict(self, feats: dict):
        """
        Returns (label_str, confidence_float, source_str)
        label_str: "normal" or "anomalous"
        source_str: "RF" if model used, "heuristic" otherwise
        """
        # build feature vector in stable order
        cols = ["pkts_per_sec", "unique_dst_ports", "avg_len", "tcp_ratio", "syn_ratio"]
        X = np.array([[feats[c] for c in cols]], dtype=float)

        if self.using_model and self.model is not None:
            # expect classes [0,1] for normal/anomalous; adjust as needed
            if hasattr(self.model, "predict_proba"):
                prob = float(
                    self.model.predict_proba(X)[0][1]
                )  # probability of anomalous
                label = "anomalous" if prob >= self.threshold else "normal"
                return label, prob, "RF"
            else:
                pred = int(self.model.predict(X)[0])
                prob = 1.0 if pred == 1 else 0.0
                label = "anomalous" if pred == 1 else "normal"
                return label, prob, "RF"
        else:
            # simple, transparent heuristic (reasonable defaults)
            score = 0.0
            if feats["pkts_per_sec"] > 60:
                score += 0.5
            if feats["syn_ratio"] > 0.4:
                score += 0.4
            if feats["unique_dst_ports"] > 15:
                score += 0.3
            prob = min(1.0, score)
            label = "anomalous" if prob >= self.threshold else "normal"
            return label, prob, "heuristic"


class Logger:
    def __init__(self, results_csv="results.csv"):
        self.results_csv = results_csv
        if not os.path.exists(self.results_csv):
            pd.DataFrame(
                columns=[
                    "ts",
                    "window_start",
                    "window_end",
                    "label",
                    "confidence",
                    "pkts_per_sec",
                    "unique_dst_ports",
                    "avg_len",
                    "tcp_ratio",
                    "syn_ratio",
                    "source",
                ]
            ).to_csv(self.results_csv, index=False)

    def log(self, feats: dict, label: str, confidence: float, source: str):
        ts = datetime.utcnow().isoformat()
        row = {
            "ts": ts,
            "window_start": feats["window_start"],
            "window_end": feats["window_end"],
            "label": label,
            "confidence": float(confidence),
            "pkts_per_sec": feats["pkts_per_sec"],
            "unique_dst_ports": feats["unique_dst_ports"],
            "avg_len": feats["avg_len"],
            "tcp_ratio": feats["tcp_ratio"],
            "syn_ratio": feats["syn_ratio"],
            "source": source,
        }
        pd.DataFrame([row]).to_csv(
            self.results_csv, mode="a", index=False, header=False
        )

        # console output
        banner = "[ALERT]" if label == "anomalous" else "[OK]"
        print(
            f"{banner} {ts} src={source} conf={confidence:.2f} "
            f"pps={feats['pkts_per_sec']:.1f} synr={feats['syn_ratio']:.2f} "
            f"uniq_ports={feats['unique_dst_ports']}"
        )


# ---------------------------
# Controller
# ---------------------------


def main():
    parser = argparse.ArgumentParser(description="Lightweight ML IDS (live traffic)")
    parser.add_argument(
        "--iface", default="any", help="Capture interface (e.g., eth0, any)"
    )
    parser.add_argument(
        "--window", type=float, default=2.0, help="Aggregation window (seconds)"
    )
    parser.add_argument(
        "--model", default="model.pkl", help="Path to RandomForest model.pkl (optional)"
    )
    parser.add_argument(
        "--threshold", type=float, default=0.6, help="Alert threshold (0-1)"
    )
    args = parser.parse_args()

    pkt_queue = queue.Queue()
    analyzer = PacketAnalyzer(args.iface, pkt_queue)
    processor = DataProcessor()
    classifier = MLClassifier(model_path=args.model, threshold=args.threshold)
    logger = Logger()

    print("=== Lightweight IDS ===")
    print(
        f"Interface: {args.iface} | Window: {args.window}s | Threshold: {args.threshold} | Model: {'RF' if classifier.using_model else 'Heuristic'}"
    )
    print("Press Ctrl+C to stop.\n")

    stop_flag = threading.Event()

    def capture_loop():
        analyzer.start()

    def window_worker():
        window = float(args.window)
        buf = []
        window_start = time.time()
        while not stop_flag.is_set():
            try:
                # drain queue non-blocking for 'window' seconds
                t_end = time.time() + window
                while time.time() < t_end:
                    try:
                        item = pkt_queue.get(timeout=0.1)
                        buf.append(item)
                    except queue.Empty:
                        pass
                window_end = time.time()
                feats = processor.compute_features(buf, window_start, window_end)
                # reset for next window
                buf = []
                window_start = window_end
                # classify & log
                label, conf, src = classifier.predict(feats)
                logger.log(feats, label, conf, src)
            except Exception as e:
                # keep running despite errors
                sys.stderr.write(f"[WARN] window error: {e}\n")
                time.sleep(0.2)

    t1 = threading.Thread(target=capture_loop, daemon=True)
    t2 = threading.Thread(target=window_worker, daemon=True)
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_flag.set()
        analyzer.stop()
        print("\nStopped.")


if __name__ == "__main__":
    main()
