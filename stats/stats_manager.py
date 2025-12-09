import time
from collections import defaultdict, Counter


class StatsManager:
    def __init__(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)
        self.source_ip_counts = defaultdict(int)
        self.large_packets = 0

    def update(self, packet):
        self.total_packets += 1
        proto = packet.get("protocol", "OTHER")
        self.protocol_counts[proto] += 1

        src_ip = packet.get("src_ip")
        if src_ip:
            self.source_ip_counts[src_ip] += 1

        if packet.get("length", 0) > 1500:
            self.large_packets += 1

    def get_stats(self):
        runtime = time.time() - self.start_time
        top_sources = dict(Counter(self.source_ip_counts).most_common(5))
        return {
            "runtime": runtime,
            "total_packets": self.total_packets,
            "protocol_counts": dict(self.protocol_counts),
            "top_sources": top_sources,
            "large_packets": self.large_packets
        }