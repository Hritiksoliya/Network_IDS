from scapy.all import sniff, IP, TCP
from collections import Counter
import time
from scapy.all import get_if_list

interfaces = get_if_list()
print("Available network interfaces:", interfaces)

syn_count = Counter()
THRESHOLD = 10  # SYN packet threshold per time window
TIME_WINDOW = 5  # Time window in seconds

# Track timestamps
start_time = time.time()


def process_packet(packet):
    global start_time

    # Ensure the packet contains an IP layer
    if not packet.haslayer(IP):
        return  # Ignore non-IP packets (ARP, STP, etc.)

    if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag only
        src_ip = packet[IP].src
        syn_count[src_ip] += 1

        # Check if time window has passed
        if time.time() - start_time > TIME_WINDOW:
            for ip, count in syn_count.items():
                if count > THRESHOLD:
                    print(f"[ALERT] Possible SYN scan detected from {ip} ({count} SYNs in {TIME_WINDOW}s)")
            # Reset counters
            syn_count.clear()
            start_time = time.time()


# Ask user for packet count
packet_count = int(input("Enter the number of packets to capture: "))

print(f"Monitoring {packet_count} packets for SYN scan detection...")
sniff(iface="\\Device\\NPF_Loopback",filter="tcp", prn=process_packet, count=packet_count, store=False)