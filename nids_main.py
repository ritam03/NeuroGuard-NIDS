import os
import pandas as pd
import numpy as np
import joblib
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import warnings
import sys

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# CONFIGURATION
MODEL_PATH = "models/nids_model.pkl"
ENCODER_PATH = "models/encoders.pkl"
LOG_FILE = "logs/alerts.txt"

# STATE TRACKING
# We track how many packets an IP sends in a short window to detect "floods"
ip_tracker = defaultdict(int)
last_reset_time = time.time()

# ENSURE DIRECTORIES EXIST
if not os.path.exists("logs"):
    os.makedirs("logs")

# LOAD THE AI BRAIN
print("----------------------------------------------------------------")
print("   🛡️  NEUROGUARD: AI-POWERED NIDS SYSTEM v1.0   🛡️")
print("----------------------------------------------------------------")
print("⏳ Loading AI Model & Encoders...")

if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
    print("❌ ERROR: Model files not found! Please run 'train_model.py' first.")
    sys.exit()

try:
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODER_PATH)
    print("AI Model Loaded Successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    sys.exit()

print("NeuroGuard Active & Sniffing... (Press Ctrl+C to Stop)")

# FEATURES LIST (Must match training data exactly)
COLUMNS = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"]

def log_alert(message):
    """Prints alert to console and saves to file for UI"""
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}"
    
    # Print to Terminal (Red Color for visibility if supported, else standard)
    print(f"🚨 {formatted_msg}")
    
    # Append to Log File
    with open(LOG_FILE, "a") as f:
        f.write(formatted_msg + "\n")

def get_service_mapping(dport):
    """Maps port numbers to service names expected by the model"""
    if dport == 80 or dport == 443: return "http"
    if dport == 21: return "ftp"
    if dport == 22: return "ssh"
    if dport == 25: return "smtp"
    if dport == 53: return "domain_u"
    return "private" # Default for unknown ports

def process_packet(packet):
    global ip_tracker, last_reset_time

    # Only process IP packets
    if not packet.haslayer(IP):
        return

    # 1. Traffic Rate Calculation (Reset count every 2 seconds)
    if time.time() - last_reset_time > 2:
        ip_tracker.clear()
        last_reset_time = time.time()
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    ip_tracker[src_ip] += 1
    packet_rate = ip_tracker[src_ip]

    try:
        # 2. Extract Features from Packet
        protocol_str = "tcp"
        service_str = "private"
        flag_str = "SF"
        src_bytes = len(packet)
        
        if packet.haslayer(TCP):
            protocol_str = "tcp"
            service_str = get_service_mapping(packet[TCP].dport)
            # Check for suspicious flags
            if packet[TCP].flags.S and not packet[TCP].flags.A: 
                flag_str = "S0" # SYN Only (Connection attempt)
            if packet[TCP].flags.R: 
                flag_str = "REJ" # Connection Rejected
            
        elif packet.haslayer(UDP):
            protocol_str = "udp"
            service_str = get_service_mapping(packet[UDP].dport)
            
        elif packet.haslayer(ICMP):
            protocol_str = "icmp"

        # 3. Encode Features (Text -> Numbers)
        def encode(enc, val):
            try:
                return enc.transform([val])[0]
            except:
                return 0 # Handle unseen labels safely
            
        p_enc = encode(encoders['protocol_type'], protocol_str)
        s_enc = encode(encoders['service'], service_str)
        f_enc = encode(encoders['flag'], flag_str)

        # 4. Build Input Vector for AI
        features = np.zeros((1, 41))
        features[0, 1] = p_enc
        features[0, 2] = s_enc
        features[0, 3] = f_enc
        features[0, 4] = src_bytes
        
        # Inject the Traffic Rate into 'count' features
        # This allows the AI to detect Flooding/DoS attacks
        features[0, 22] = packet_rate  # count
        features[0, 23] = packet_rate  # srv_count
        
        # 5. Predict (0 = Normal, 1 = Attack)
        df_in = pd.DataFrame(features, columns=COLUMNS)
        pred = model.predict(df_in)[0]

        # 6. Action
        if pred == 1:
            # MALICIOUS TRAFFIC
            log_alert(f"MALICIOUS: {src_ip} -> {dst_ip} | {protocol_str.upper()} | Rate: {packet_rate}")
        else:
            # NORMAL TRAFFIC (Printed to console as requested)
            print(f"✅ [Normal] {src_ip} -> {dst_ip} | {protocol_str.upper()} | Service: {service_str} | Rate: {packet_rate}")

    except Exception as e:
        # Skip malformed packets
        pass

# START SNIFFER
# store=0 prevents saving packets to RAM (avoids memory crash)
try:
    scapy.sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nNIDS Stopped by User.")
except Exception as e:
    print(f"\nSniffer Error: {e}")
    print("Tip: Try running VS Code as Administrator.")