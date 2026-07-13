import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff
from scapy.all import Raw
from scapy.layers.inet import IP, TCP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD} packets/sec")

# Global tracking structures
packet_timestamps = defaultdict(list)  # Reverted to robust sliding window
blocked_ips = set()
whitelist_ips = set()
blacklist_ips = set()

def read_ip_file(filename):
    """Safely reads IPs from a file, returning an empty set if missing."""
    if not os.path.exists(filename):
        print(f"Warning: {filename} not found. Creating empty file.")
        with open(filename, "w") as f:
            pass
        return set()
    with open(filename, "r") as file:
        return {line.strip() for line in file if line.strip()}

def is_nimda_worm(packet):
    """Accurately checks for the Nimda worm signature using byte matching."""
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if packet.haslayer(Raw):
            return b"GET /scripts/root.exe" in packet[Raw].load
    return False

def log_event(message):
    """Logs events into a centralized monthly/daily log file instead of hundreds of files."""
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    date_str = time.strftime("%Y-%m-%d", time.localtime())
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    log_file = os.path.join(log_folder, f"ips_log_{date_str}.txt")

    with open(log_file, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # CRITICAL FIX: Ignore already blocked IPs immediately to prevent duplicate rules
    if src_ip in blocked_ips or src_ip in whitelist_ips:
        return

    # Check Static Blacklist
    if src_ip in blacklist_ips:
        print(f"Blocking blacklisted IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        blocked_ips.add(src_ip)
        return

    # Check Signature (Nimda Worm)
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        blocked_ips.add(src_ip)
        return

    # Anomaly Detection: Sliding Window Rate Limiter
    current_time = time.time()
    packet_timestamps[src_ip].append(current_time)
    packet_timestamps[src_ip] = [t for t in packet_timestamps[src_ip] if current_time - t <= 1.0]

    packet_rate = len(packet_timestamps[src_ip])

    if packet_rate > THRESHOLD:
        print(f"Blocking IP due to rate limit: {src_ip} | Rate: {packet_rate} pkts/sec")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking IP due to rate limit: {src_ip} | Rate: {packet_rate} pkts/sec")
        blocked_ips.add(src_ip)
        if src_ip in packet_timestamps:
            del packet_timestamps[src_ip]

if __name__ == "__main__":
    # Ensure root privileges on Linux
    if os.getuid() != 0:
        print("Error: This script requires root (sudo) privileges.")
        sys.exit(1)

    # Load files safely
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    print("Monitoring network traffic on Linux... Press Ctrl+C to stop.")
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopping monitor.")