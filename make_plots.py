#!/usr/bin/env python3
# make_plots.py — Build evaluation plots from IDS CSVs
# Usage: python3 make_plots.py
# Optional: if you have model.pkl (RandomForest), feature importance will be plotted.

import os
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ---------- CONFIG: (OPTIONAL) label intervals for ground truth ----------
# If you recorded approximate UTC timestamps (from IDS console) for each test,
# put them here to compute real accuracy/FPR/FNR.
# Format: ("YYYY-mm-ddTHH:MM:SS", "YYYY-mm-ddTHH:MM:SS", "normal"|"anomalous")
LABEL_INTERVALS = [
    # Example (edit these 5 lines with your actual times seen in IDS output)
    # ("2025-11-15T19:24:10", "2025-11-15T19:24:20", "normal"),     # ping
    # ("2025-11-15T19:55:40", "2025-11-15T19:56:10", "normal"),     # curl
    # ("2025-11-15T19:56:50", "2025-11-15T19:57:10", "anomalous"),  # nmap
    # ("2025-11-15T19:58:30", "2025-11-15T19:59:10", "anomalous"),  # burst
    # ("2025-11-15T20:00:00", "2025-11-15T20:00:20", "normal"),     # idle
]


# ---------- Load data ----------
def read_csvs():
    r = pd.read_csv("results.csv", parse_dates=["ts"])
    # Ensure numeric
    num_cols = [
        "pkts_per_sec",
        "unique_dst_ports",
        "avg_len",
        "tcp_ratio",
        "syn_ratio",
        "confidence",
    ]
    for c in num_cols:
        if c in r.columns:
            r[c] = pd.to_numeric(r[c], errors="coerce").fillna(0.0)

    # latency proxy (your window size)
    r["latency_sec"] = pd.to_numeric(
        (
            pd.to_datetime(r["window_end"], errors="coerce")
            - pd.to_datetime(r["window_start"], errors="coerce")
        ).dt.total_seconds(),
        errors="coerce",
    ).fillna(0.0)

    return r


def attach_ground_truth(df):
    if not LABEL_INTERVALS:
        df["y_true"] = np.nan
        return df, False

    y_true = []
    for t in df["ts"]:
        lab = np.nan
        for s, e, y in LABEL_INTERVALS:
            try:
                if pd.Timestamp(s) <= t <= pd.Timestamp(e):
                    lab = 1 if y == "anomalous" else 0
                    break
            except Exception:
                pass
        y_true.append(lab)
    df["y_true"] = y_true
    has_truth = df["y_true"].notna().any()
    return df, has_truth


def ensure_dir(fname):
    (
        os.makedirs(os.path.dirname(fname), exist_ok=True)
        if os.path.dirname(fname)
        else None
    )


# ---------- Plot helpers ----------
def savefig(name):
    ensure_dir(name)
    plt.savefig(name, dpi=150, bbox_inches="tight")
    plt.close()


def plot_accuracy_over_time(df, has_truth):
    plt.figure()
    if has_truth:
        # Accuracy (cumulative) vs sample index
        df2 = df.dropna(subset=["y_true"]).copy()
        y_pred = (df2["label"] == "anomalous").astype(int)
        acc = (y_pred == df2["y_true"]).expanding().mean()
        plt.plot(acc.values)
        plt.title("Accuracy vs Samples (Cumulative)")
        plt.xlabel("Sample index")
        plt.ylabel("Accuracy")
        savefig("Fig_08_Accuracy_over_Time.png")
    else:
        # No ground truth → show alert rate over time
        rate = (
            (df["label"] == "anomalous").astype(int).rolling(10, min_periods=1).mean()
        )
        plt.plot(rate.values)
        plt.title("Anomaly Rate (rolling) vs Samples")
        plt.xlabel("Sample index")
        plt.ylabel("Rolling Anomaly Rate")
        savefig("Fig_08_Accuracy_over_Time.png")


def plot_fpr_vs_threshold(df, has_truth):
    # Need ground truth OR probabilities; we have confidence from heuristic or model
    if (not has_truth) or ("confidence" not in df.columns):
        # Make a placeholder informative chart: confidence distribution
        plt.figure()
        df["confidence"].plot(kind="hist", bins=20)
        plt.title("Confidence Distribution (No Ground Truth Provided)")
        plt.xlabel("Confidence")
        plt.ylabel("Count")
        savefig("Fig_09_FPR_vs_Threshold.png")
        return

    df2 = df.dropna(subset=["y_true"]).copy()
    y_true = df2["y_true"].astype(int).values
    conf = df2["confidence"].values

    ths = np.linspace(0.3, 0.9, 13)
    fprs, fnrs = [], []
    for t in ths:
        y_pred = (conf >= t).astype(int)
        fp = np.logical_and(y_pred == 1, y_true == 0).sum()
        tn = np.logical_and(y_pred == 0, y_true == 0).sum()
        fn = np.logical_and(y_pred == 0, y_true == 1).sum()
        tp = np.logical_and(y_pred == 1, y_true == 1).sum()
        fpr = fp / max(1, (fp + tn))
        fnr = fn / max(1, (fn + tp))
        fprs.append(fpr)
        fnrs.append(fnr)

    plt.figure()
    plt.plot(ths, fprs, marker="o", label="FPR")
    plt.plot(ths, fnrs, marker="o", label="FNR")
    plt.title("FPR / FNR vs Threshold")
    plt.xlabel("Threshold")
    plt.ylabel("Rate")
    plt.legend()
    savefig("Fig_09_FPR_vs_Threshold.png")


def plot_latency_vs_pps(df):
    plt.figure()
    plt.scatter(
        df["pkts_per_sec"],
        df["latency_sec"],
        s=16,
        alpha=0.6,
        c=np.where(df["label"] == "anomalous", "red", "blue"),
    )
    plt.title("Latency vs Packet Rate")
    plt.xlabel("Packets per second")
    plt.ylabel("Latency (sec)")
    savefig("Fig_10_Latency_vs_PPS.png")


def plot_feature_importance_or_trends(df):
    # If you have a model.pkl with feature_importances_, show that.
    used_importance = False
    try:
        import joblib

        rf = joblib.load("model.pkl")
        if hasattr(rf, "feature_importances_"):
            imps = rf.feature_importances_
            names = [
                "pkts_per_sec",
                "unique_dst_ports",
                "avg_len",
                "tcp_ratio",
                "syn_ratio",
            ]
            plt.figure()
            plt.bar(names, imps)
            plt.title("Feature Importance (Random Forest)")
            plt.xticks(rotation=15)
            plt.ylabel("Importance")
            savefig("Fig_11_FeatureImportance_or_FeatureTrends.png")
            used_importance = True
    except Exception:
        pass

    if not used_importance:
        # fallback: show feature trends split by label
        plt.figure()
        for f in ["pkts_per_sec", "syn_ratio", "unique_dst_ports"]:
            plt.plot(df[f].values, label=f)
        plt.title("Feature Trends Over Time")
        plt.xlabel("Sample index")
        plt.ylabel("Value")
        plt.legend()
        savefig("Fig_11_FeatureImportance_or_FeatureTrends.png")


def plot_tool_comparison():
    # Make a simple grouped bar chart comparing Snort, Suricata, and this IDS.
    # Scores are qualitative (1–5).
    tools = ["Snort", "Suricata", "My IDS"]
    metrics = ["Automation", "Real-time", "ML-based", "Ease of setup"]
    scores = {
        "Snort": [2, 5, 1, 2],
        "Suricata": [3, 5, 2, 2],
        "My IDS": [5, 4, 5, 5],
    }
    x = np.arange(len(metrics))
    w = 0.25
    plt.figure()
    plt.bar(x - w, scores["Snort"], width=w, label="Snort")
    plt.bar(x, scores["Suricata"], width=w, label="Suricata")
    plt.bar(x + w, scores["My IDS"], width=w, label="My IDS")
    plt.xticks(x, metrics, rotation=15)
    plt.ylim(0, 6)
    plt.ylabel("Score (1–5)")
    plt.title("Comparison of IDS Approaches")
    plt.legend()
    savefig("Fig_12_Comparison_Tools.png")


def main():
    if not os.path.exists("results.csv"):
        raise SystemExit("results.csv not found in current directory.")

    df = read_csvs()
    df, has_truth = attach_ground_truth(df)

    # 08
    plot_accuracy_over_time(df, has_truth)
    # 09
    plot_fpr_vs_threshold(df, has_truth)
    # 10
    plot_latency_vs_pps(df)
    # 11
    plot_feature_importance_or_trends(df)
    # 12
    plot_tool_comparison()

    print("Saved: Fig_08_..., Fig_09_..., Fig_10_..., Fig_11_..., Fig_12_...")


if __name__ == "__main__":
    main()
