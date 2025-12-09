# capture/sniffer.py
from scapy.all import sniff

def capture_packets(packet_count=50, iface=None, bpf_filter=None, timeout=None):
    """
    Capture packets using scapy.sniff with optional interface and BPF filter.

    - packet_count: number of packets to capture (None for unlimited until timeout)
    - iface: interface name (None uses default)
    - bpf_filter: libpcap BPF filter string, e.g., "tcp", "udp", "icmp", "arp", "tcp and port 80"
    - timeout: seconds to capture (None means no timeout)
    """
    options = {}
    if iface:
        options['iface'] = iface
    if bpf_filter:
        options['filter'] = bpf_filter
    if timeout:
        options['timeout'] = timeout

    print(f"[*] Starting capture: count={packet_count}, filter={bpf_filter}, iface={iface}, timeout={timeout}")
    packets = sniff(count=packet_count, **options)
    print("[*] Capture completed.")
    return packets
