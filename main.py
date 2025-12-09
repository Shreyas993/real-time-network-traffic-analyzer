from capture.sniffer import capture_packets
from analysis.parser import parse_packet, analyze_packets
from utils.logger import save_to_csv, log_event
from stats.stats_manager import StatsManager
from visuals.plotter import plot_protocol_distribution, plot_top_ips
from gui.dashboard_gui import PacketDashboard
from colorama import Fore, Style, init
import threading
import time

# Initialize colorama for console output
init(autoreset=True)


def choose_filter():
    print("Choose a capture filter:")
    print("1) All packets (no filter)")
    print("2) TCP")
    print("3) UDP")
    print("4) ICMP")
    print("5) ARP")
    print("6) Custom BPF filter (enter manually)")
    choice = input("Enter choice [1-6]: ").strip()

    if choice == "1":
        return None
    elif choice == "2":
        return "tcp"
    elif choice == "3":
        return "udp"
    elif choice == "4":
        return "icmp"
    elif choice == "5":
        return "arp"
    elif choice == "6":
        custom = input("Enter BPF filter (example: 'tcp and port 80'): ").strip()
        return custom if custom else None
    else:
        print("Invalid choice — defaulting to no filter.")
        return None


def main():
    print("\n=== Network Traffic Analyzer ===\n")

    bpf = choose_filter()

    count_input = input("Enter packet count to capture (default 30): ").strip()
    try:
        pkt_count = int(count_input) if count_input else 30
    except ValueError:
        print("Invalid number, defaulting to 30.")
        pkt_count = 30

    # Stats manager tracks packets for live dashboard
    stats = StatsManager()

    # Start GUI dashboard in a separate thread
    gui_thread = threading.Thread(target=PacketDashboard, args=(stats,), daemon=True)
    gui_thread.start()

    print(f"\nCapturing {pkt_count} packets... Press Ctrl+C to stop early.\n")
    packets = capture_packets(packet_count=pkt_count, bpf_filter=bpf)
    print(f"\nTotal packets captured: {len(packets)}\n")
    print("Analyzing packets...\n")

    parsed_data = []

    for pkt in packets:
        parsed = parse_packet(pkt)
        parsed_data.append(parsed)
        stats.update(parsed)  # update stats for live dashboard

        # Console color-coded output
        proto = parsed["protocol"]
        if proto == "TCP":
            color = Fore.GREEN
        elif proto == "UDP":
            color = Fore.BLUE
        elif proto == "ICMP":
            color = Fore.YELLOW
        elif proto == "ARP":
            color = Fore.MAGENTA
        else:
            color = Fore.WHITE

        size_warning = Fore.RED + " [LARGE]" if parsed["length"] > 1500 else ""
        print(f"{color}{parsed}{Style.RESET_ALL}{size_warning}")

    time.sleep(0.5)

    print("\nPacket analysis complete.\nSaving results to CSV...")
    csv_file = save_to_csv(parsed_data)

    # Static plots for portfolio/report
    plot_protocol_distribution(parsed_data)
    plot_top_ips(parsed_data)

    summary = analyze_packets(parsed_data)
    print("\n=== Summary ===")
    for proto, count in summary.items():
        print(f"{proto}: {count}")

    live_stats = stats.get_stats()
    print("\n=== Final Live Stats ===")
    print(f"Runtime (seconds): {live_stats['runtime']:.2f}")
    print(f"Total Packets: {live_stats['total_packets']}")
    print(f"Protocol Counts: {live_stats['protocol_counts']}")
    print(f"Top Source IPs: {live_stats['top_sources']}")
    print(f"Large Packets (>1500 bytes): {live_stats['large_packets']}")

    log_event(f"Capture completed. Packets: {len(parsed_data)}. CSV: {csv_file}")

    # Keep GUI alive after capture
    print("\nGUI dashboard is running. Close the window to exit.")
    gui_thread.join()


if __name__ == "__main__":
    main()
