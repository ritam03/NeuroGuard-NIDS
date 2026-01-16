import streamlit as st
import time
import os

LOG_FILE = "logs/alerts.txt"

st.set_page_config(page_title="NeuroGuard AI", layout="wide")

st.title("🛡️ NeuroGuard: Network Intrusion Detection")
st.markdown("---")

# Metrics
col1, col2, col3 = st.columns(3)
placeholder_metrics = st.empty()

# Logs Area
st.subheader("🚨 Live Threat Feed")
placeholder_logs = st.empty()

def read_logs():
    if not os.path.exists(LOG_FILE): return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()

while True:
    logs = read_logs()
    
    # Calculate Stats
    total_alerts = len(logs)
    unique_ips = len(set([l.split()[2] for l in logs if len(l.split()) > 3])) if logs else 0
    
    with placeholder_metrics.container():
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Threats", total_alerts)
        c2.metric("Attackers (Source IPs)", unique_ips)
        c3.metric("System Status", "ACTIVE 🟢")

    with placeholder_logs.container():
        if logs:
            for line in reversed(logs[-10:]): # Show last 10
                st.error(line.strip())
        else:
            st.success("No active threats detected. Network is secure.")
            
    time.sleep(1)