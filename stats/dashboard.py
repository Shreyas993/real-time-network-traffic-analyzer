import time
from colorama import Fore, Style, init

init(autoreset=True)


def render_live_stats(stats_manager):
    try:
        while True:
            live_stats = stats_manager.get_stats()
            print("\n=== LIVE PACKET STATS ===")
            print(f"Runtime (s): {live_stats['runtime']:.2f}")
            print(f"Total Packets: {live_stats['total_packets']}\n")

            print("Protocol Counts:")
            for proto, count in live_stats["protocol_counts"].items():
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
                print(f"  {color}{proto}: {count}{Style.RESET_ALL}")

            print("\nTop Source IPs:")
            for ip, count in live_stats["top_sources"].items():
                if ip is None:
                    continue
                if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
                    color = Fore.CYAN
                else:
                    color = Fore.RED
                print(f"  {color}{ip}: {count}{Style.RESET_ALL}")

            print(Fore.RED + f"\nLarge packets (>1500 bytes): {live_stats['large_packets']}" + Style.RESET_ALL)
            print("\nPress Ctrl+C to stop live stats.")
            time.sleep(1)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nLive stats stopped by user." + Style.RESET_ALL)
