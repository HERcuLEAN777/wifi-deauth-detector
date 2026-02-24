\# Wi-Fi Deauthentication Detection \& Monitoring Tool



\## Overview

This project is a defensive cybersecurity tool that passively monitors Wi-Fi traffic to detect suspicious bursts of 802.11 deauthentication frames, a common technique used in Wi-Fi denial-of-service (DoS) attacks.



The system captures wireless packets in monitor mode, analyzes management frames, tracks suspicious MAC addresses, and provides real-time monitoring via a Streamlit dashboard.



---



\## Problem Addressed

Deauthentication attacks can forcibly disconnect devices from Wi-Fi networks by sending forged management frames. These attacks are easy to launch and difficult for users to notice.



This tool helps identify such activity through packet inspection and anomaly detection.



---



\## ✅ Features

\- Deauthentication frame detection

\- Attacker MAC address tracking

\- Threshold-based attack detection

\- Real-time monitoring dashboard

\- Visual frame distribution analytics

\- Severity / risk indicator



---



\## Technologies Used

\- Python

\- Scapy (Packet Analysis)

\- Streamlit (Dashboard UI)

\- Pandas (Data Handling)



---



\## Requirements

\- Linux (Kali / Ubuntu recommended)

\- Wi-Fi Adapter supporting Monitor Mode



---



\## Usage

1\. Enable monitor mode on wireless adapter

2\. Run detector script

3\. Launch Streamlit dashboard



---



\## ⚠️ Legal \& Ethical Disclaimer

This project is strictly for \*\*educational and defensive security research purposes\*\*.



Use only on networks you own or have explicit permission to monitor.

