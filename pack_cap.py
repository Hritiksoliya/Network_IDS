from scapy.all import sniff, IP, TCP, UDP,ICMPv6EchoRequest,get_if_list,IPv6
import time
from collections import Counter
from scapy.layers.inet import ICMP
from colorama import Fore, Style, init



interfaces = get_if_list()
ICMP_LARGE_THRESHOLD=1000
malicious_ips = {
    "192.168.164.23": "Internal Attack Source",
    "45.33.32.156": "Known Botnet IP",
    "103.21.244.0": "Suspicious VPN Exit Node"
}


print("Available network interfaces:", interfaces)
# List to store captured packet data
packet_data = []
syn_count = Counter()
THRESHOLD = 10  # SYN packet threshold per time window
TIME_WINDOW = 5  # Time window in seconds

# Track timestamps
start_time = time.time()

print_packet=False
# Function to process each captured packet
def process_packet(packet):
    try:
        # *-------------------------------------------------------------------------------------------------------*#
        if print_packet:
            src_ip = dst_ip = proto = "Unknown"
            pkt_size = len(packet)
            if packet.haslayer(IP):  # IPv4 Packet
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
            elif packet.haslayer(IPv6):  # IPv6 Packet
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                proto = "IPv6"
            # Identify Transport Layer Protocol
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
            # Print packet info in one line
            print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {proto} | Size: {pkt_size} bytes")

    # *-------------------------------------------------------------------------------------------------------*#
        global start_time
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag only
            src_ip = packet[IP].src
            syn_count[src_ip] += 1

            # Check if time window has passed
            if time.time() - start_time > TIME_WINDOW:
                for ip, count in syn_count.items():
                    if count > THRESHOLD:
                        print(Fore.RED +f"[ALERT] Possible SYN scan detected from {ip} ({count} SYNs in {TIME_WINDOW}s)"+ Style.RESET_ALL)
                # Reset counters
                syn_count.clear()
                start_time = time.time()
    # *-------------------------------------------------------------------------------------------------------*#
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)  # Get packet size

            # Print all captured ICMP packets
            # print(f"ICMP IPv4 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")

            # Alert if the packet is larger than the threshold
            if pkt_size > ICMP_LARGE_THRESHOLD:
                print(Fore.RED +f"[ALERT] Large ICMP packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)"+ Style.RESET_ALL)

    # *-------------------------------------------------------------------------------------------------------*#

    # icmp packet analysis
        if packet.haslayer(ICMPv6EchoRequest) and packet.haslayer(IPv6):  # IPv6 ICMP
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            pkt_size = len(packet)
            # print(f"ICMPv6 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")
            if pkt_size > ICMP_LARGE_THRESHOLD:
                print(Fore.RED +f"[ALERT] Large ICMPv6 packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)"+ Style.RESET_ALL)
    #*-------------------------------------------------------------------------------------------------------*#
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
                print(Fore.RED +f"[ALERT] Large packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)"+ Style.RESET_ALL)
            # if proto == 6 and packet.haslayer(TCP) and packet[TCP].flags == 2:
            #     print(f"[WARNING] SYN packet detected from {src_ip} (Possible scan attack)")

            # if packet.haslayer(TCP):  # Check if the packet contains a TCP layer
            #     print(packet.summary())

#*---------------------------------------------------------------------------------------------------*#
            #check for the malicious ips
        if packet.haslayer(IP):  # Check if the packet contains an IP layer
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            pkt_size = len(packet)

            # Check if source IP is malicious
            if src_ip in malicious_ips:
                print(Fore.RED +f"[ALERT] Malicious source IP detected: {src_ip} ({malicious_ips[src_ip]})"+ Style.RESET_ALL)

            # Check if destination IP is malicious
            if dst_ip in malicious_ips:
                print(Fore.RED +f"[ALERT] Malicious destination IP detected: {dst_ip} ({malicious_ips[dst_ip]})"+ Style.RESET_ALL)

            # Print packet details for logging or further analysis
            # print(f"Packet: {src_ip} -> {dst_ip} | Protocol: {proto} | Size: {pkt_size} bytes")
    except Exception as e:
        print(Fore.YELLOW + f"[WARNING] Skipped a non-IP packet: {e}" + Style.RESET_ALL)