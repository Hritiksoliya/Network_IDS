from scapy.all import get_if_list
from scapy.all import sniff, IP, TCP

interfaces = get_if_list()
print("Available network interfaces:", interfaces)
def process_packet(packet):

    if packet.haslayer(IP):
        print(f"Captured Packet: {packet[IP].src} → {packet[IP].dst} (Protocol: {packet.proto})")

# Capture packets from all interfaces
sniff(iface=interfaces, prn=process_packet, store=False)