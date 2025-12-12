# H-LIDS: Heuristic Lightweight Intrusion Detection System
Senior Design Project – CSC/ITC 492  
Author: John Henry Mejia  
Instructor: Dr. Tang  
Fall 2025

## Description
H-LIDS is a lightweight Intrusion Detection System that captures, processes, and analyzes live network traffic using a heuristic anomaly detection method. It is designed for educational and small-scale network environments.

## Features
- Live packet capture using Scapy
- Feature extraction (pkts/sec, SYN ratio, unique ports)
- Heuristic-based anomaly scoring
- Real-time alert display (OK / ALERT)
- CSV logging of features and detection results
- Evaluation plot generator (Matplotlib)

## Running the IDS
In Ubuntu (WSL) navigate to the file path:
/mnt/c/Users/"John Henry"/Documents/School/H-LIDS

Start the program:
sudo -E python3 ids.py --iface lo --window 2.0 --threshold 0.6


## Running the Evaluation Plot Generator
python3 make_plots.py


## Notes
This version uses heuristic detection.  
A trained Random Forest model is NOT implemented but is supported for future development.

## Project Report Link
(Insert your PDF link if needed)
