import matplotlib.pyplot as plt
import os

VISUALS_DIR = "visuals"
os.makedirs(VISUALS_DIR, exist_ok=True)

def plot_protocol_distribution(parsed_packets):
    """
    Creates a pie chart of protocol distribution and saves it.
    """
    protocol_counts = {}
    for pkt in parsed_packets:
        proto = pkt.get("protocol", "OTHER")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    if not protocol_counts:
        print("[!] No protocol data to plot.")
        return

    labels = protocol_counts.keys()
    sizes = protocol_counts.values()

    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Protocol Distribution")
    filename = os.path.join(VISUALS_DIR, "protocol_distribution.png")
    plt.savefig(filename)
    plt.close()
    print(f"[+] Protocol distribution chart saved: {filename}")


def plot_top_ips(parsed_packets, top_n=5):
    """
    Creates a bar chart of top source IPs and saves it.
    Filters out None or missing IPs.
    """
    ip_counts = {}
    for pkt in parsed_packets:
        src = pkt.get("src_ip")
        if src is None:
            continue  # Skip packets without a source IP
        ip_counts[src] = ip_counts.get(src, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    if not top_ips:
        print("[!] No valid source IPs to plot.")
        return

    ips, counts = zip(*top_ips)

    plt.figure(figsize=(8,5))
    plt.bar(ips, counts, color='skyblue')
    plt.title(f"Top {top_n} Source IPs")
    plt.xlabel("IP Address")
    plt.ylabel("Packet Count")
    filename = os.path.join(VISUALS_DIR, "top_source_ips.png")
    plt.savefig(filename)
    plt.close()
    print(f"[+] Top source IPs chart saved: {filename}")
