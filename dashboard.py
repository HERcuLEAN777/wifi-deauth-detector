import streamlit as st
import json
import time
import pandas as pd
import os

st.set_page_config(page_title="Wi-Fi Deauth Monitor", layout="wide")

# ---- Dark Theme Styling ----
st.markdown("""
    <style>
        body {
            background-color: #0E1117;
            color: white;
        }
        .stApp {
            background-color: #0E1117;
        }
    </style>
""", unsafe_allow_html=True)

st.title("📡 Wi-Fi Deauthentication Detection Dashboard")

DATA_FILE = "detections.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"total_frames": 0, "mac_stats": {}, "timestamp": time.time()}

    with open(DATA_FILE, "r") as f:
        return json.load(f)

data = load_data()

total_frames = data.get("total_frames", 0)
mac_stats = data.get("mac_stats", {})
timestamp = data.get("timestamp", time.time())

# ---- Session Tracking for Attack Rate ----
if "prev_frames" not in st.session_state:
    st.session_state.prev_frames = total_frames
    st.session_state.prev_time = timestamp

time_diff = max(timestamp - st.session_state.prev_time, 1)
frame_diff = total_frames - st.session_state.prev_frames

attack_rate = frame_diff / time_diff

st.session_state.prev_frames = total_frames
st.session_state.prev_time = timestamp

# ---- Metrics Row ----
col1, col2, col3 = st.columns(3)

col1.metric("Total Deauth Frames", total_frames)
col2.metric("Suspicious Devices", len(mac_stats))
col3.metric("Attack Rate (frames/sec)", f"{attack_rate:.2f}")

st.divider()

# ---- Severity Logic ----
if attack_rate > 5:
    st.error("🚨 HIGH RISK: Active Deauthentication Attack Detected")
elif attack_rate > 1:
    st.warning("⚠️ Suspicious Activity Detected")
else:
    st.success("✅ Network Activity Normal")

# ---- Data Table ----
st.subheader("📋 Detected Senders")

df = pd.DataFrame([
    {"MAC Address": mac, "Frames Sent": count}
    for mac, count in mac_stats.items()
])

st.dataframe(df, use_container_width=True)

# ---- Charts Section ----
if not df.empty:

    st.subheader("📊 Frame Distribution by Device")
    st.bar_chart(df.set_index("MAC Address"))

    # ---- Top Attacker ----
    top_attacker = df.sort_values("Frames Sent", ascending=False).iloc[0]

    st.subheader("🎯 Top Sender")
    st.info(f"MAC Address: {top_attacker['MAC Address']} | Frames: {top_attacker['Frames Sent']}")

# ---- Auto Refresh ----
time.sleep(2)
st.rerun()