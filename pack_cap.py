from scapy.all import sniff, IP, TCP, UDP,ICMPv6EchoRequest,get_if_list,IPv6
import pandas as pd
import time
from collections import Counter
from scapy.layers.inet import ICMP

interfaces = get_if_list()
ICMP_LARGE_THRESHOLD=1000

print("Available network interfaces:", interfaces)
# List to store captured packet data
packet_data = []
syn_count = Counter()
THRESHOLD = 10  # SYN packet threshold per time window
TIME_WINDOW = 5  # Time window in seconds

# Track timestamps
start_time = time.time()


# Function to process each captured packet
def process_packet(packet):
    global start_time
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

    if packet.haslayer(ICMP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_size = len(packet)  # Get packet size

        # Print all captured ICMP packets
        print(f"ICMP IPv4 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")

        # Alert if the packet is larger than the threshold
        if pkt_size > ICMP_LARGE_THRESHOLD:
            print(f"[ALERT] Large ICMP packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)")


# icmp packet analysis
    if packet.haslayer(ICMPv6EchoRequest) and packet.haslayer(IPv6):  # IPv6 ICMP
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        pkt_size = len(packet)
        print(f"ICMPv6 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")
        if pkt_size > ICMP_LARGE_THRESHOLD:
            print(f"[ALERT] Large ICMPv6 packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)")

    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        pkt_size = len(packet)

        # Store packet details
        packet_data.append({
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": proto,
            "Packet Size": pkt_size
        })

        # Simple anomaly detection rules
        if pkt_size > 1500:  # Large packet anomaly
            print(f"[ALERT] Large packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)")

        # if proto == 6 and packet.haslayer(TCP) and packet[TCP].flags == 2:
        #     print(f"[WARNING] SYN packet detected from {src_ip} (Possible scan attack)")

        # if packet.haslayer(TCP):  # Check if the packet contains a TCP layer
        #     print(packet.summary())





# Ask user for packet count
packet_count = int(input("Enter the number of packets to capture: "))

# Start capturing packets
print(f"Starting packet capture for {packet_count} packets...")

sniff(iface=interfaces, prn=process_packet, count=packet_count, store=False)


# Convert captured data to a DataFrame
df = pd.DataFrame(packet_data)
print("\nCaptured Packet Summary:")
print(df.head())

# Analyze packet distribution
print("\nTop 5 Source IPs:")
print(Counter(df["Source IP"]).most_common(5))



#check tcp
# netsh trace start capture=yes maxsize=500 filemode=single tracefile=C:\temp\trace.etl
