# analysis/parser.py
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

def parse_packet(packet):
    data = {
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet)
    }

    # IP packet (TCP/UDP/ICMP)
    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst

        # TCP
        if packet.haslayer(TCP):
            data["protocol"] = "TCP"
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport

        # UDP
        elif packet.haslayer(UDP):
            data["protocol"] = "UDP"
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

        # ICMP
        elif packet.haslayer(ICMP):
            data["protocol"] = "ICMP"

        else:
            data["protocol"] = "IP"

    # ARP packet
    elif packet.haslayer(ARP):
        data["protocol"] = "ARP"
        data["src_ip"] = packet[ARP].psrc
        data["dst_ip"] = packet[ARP].pdst

    else:
        data["protocol"] = "OTHER"

    return data


def analyze_packets(parsed_list):
    """
    A basic summarizer to count packets by protocol.
    """
    summary = {}

    for pkt in parsed_list:
        proto = pkt.get("protocol", "UNKNOWN")
        summary[proto] = summary.get(proto, 0) + 1

    return summary
