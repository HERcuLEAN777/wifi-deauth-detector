from scapy.all import *
from scapy.layers.dot11 import Dot11
from collections import defaultdict
import time
import json
import os

mac_stats = defaultdict(int)
total_frames = 0

OUTPUT_FILE = "detections.json"
THRESHOLD = 20
WINDOW = 10

start_time = time.time()
window_count = 0

def save_data():
    data = {
        "total_frames": total_frames,
        "mac_stats": dict(mac_stats),
        "timestamp": time.time()
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

def packet_handler(pkt):
    global total_frames, window_count, start_time

    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 12:  # Deauthentication frame

            sender = pkt.addr2
            mac_stats[sender] += 1

            total_frames += 1
            window_count += 1

            print(f"[!] Deauth Frame Detected → {sender}")
            save_data()

    elapsed = time.time() - start_time

    if elapsed > WINDOW:
        if window_count > THRESHOLD:
            print("🚨 Possible Deauthentication Attack Detected!")

        window_count = 0
        start_time = time.time()

print("[*] Monitoring Wi-Fi Traffic for Deauthentication Frames...")
sniff(iface="wlan0mon", prn=packet_handler, store=0)