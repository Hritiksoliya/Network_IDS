from scapy.all import sniff, IP, ICMP,ICMPv6EchoRequest,IPv6

from scapy.all import get_if_list
interfaces = get_if_list()
# Define ICMP packet size threshold
ICMP_LARGE_THRESHOLD = 1000  # Bytes

# Function to process ICMP packets
def process_icmp_packet(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_size = len(packet)  # Get packet size

        # Print all captured ICMP packets
        print(f"ICMP IPv4 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")

        # Alert if the packet is larger than the threshold
        if pkt_size > ICMP_LARGE_THRESHOLD:
            print(f"[ALERT] Large ICMP packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)")

    if packet.haslayer(ICMPv6EchoRequest) and packet.haslayer(IPv6):  # IPv6 ICMP
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        pkt_size = len(packet)
        print(f"ICMPv6 Packet: {src_ip} -> {dst_ip} | Size: {pkt_size} bytes")
        if pkt_size > ICMP_LARGE_THRESHOLD:
            print(f"[ALERT] Large ICMPv6 packet detected from {src_ip} to {dst_ip} (Size: {pkt_size} bytes)")


# Ask the user for packet count
packet_count = int(input("Enter the number of ICMP packets to capture: "))

# Start sniffing only ICMP packets
print(f"Capturing {packet_count} ICMP packets...")
sniff(iface=interfaces,filter="icmp", prn=process_icmp_packet, count=packet_count, store=False)

print("packet scanning done")

