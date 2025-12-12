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

##Test commands
- ping -c 10 127.0.0.1
	Generates normal ICMP echo requests to test basic connectivity. This represents routine network activity and should not trigger an alert.

- curl -s https://google.com
	Simulates a standard HTTPS web request. This mimics normal user browsing behavior and is classified as normal traffic.

- nmap -sT 127.0.0.1
	Performs a TCP port scan by attempting connections across multiple ports. This behavior is commonly associated with reconnaissance and triggers alerts due to spikes in 	SYN activity and destination port diversity.

- for i in {1..50}; do curl -s https://google.com > /dev/null & done; wait
	Generates a sudden burst of outbound traffic in a short time window. This simulates abnormal behavior such as early-stage denial-of-service activity and triggers alerts 	due to high packet rates.

- ls -lh *.csv
	Displays the logged detection results. This confirms that all traffic windows and alert decisions are recorded for evaluation and reproducibility.


## Running the Evaluation Plot Generator
python3 make_plots.py


## Notes
This version uses heuristic detection.  
A trained Random Forest model is NOT implemented but is supported for future development.

## Project Report Link
(Insert your PDF link if needed)
