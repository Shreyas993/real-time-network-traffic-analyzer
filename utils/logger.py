# utils/logger.py
import csv
import os
from datetime import datetime

LOG_DIR = "logs"
APP_LOG = os.path.join(LOG_DIR, "app.log")

def save_to_csv(parsed_packets):
    """
    Save parsed packet dicts into a timestamped CSV inside the logs/ folder.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{LOG_DIR}/capture_{timestamp}.csv"

    # Ensure we don't modify the original dicts in-place in a problematic way
    rows = []
    for packet in parsed_packets:
        row = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "protocol": packet.get("protocol"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "length": packet.get("length")
        }
        rows.append(row)

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"\n[+] Log saved: {filename}")
    return filename


def log_event(message):
    """
    Append simple events to logs/app.log with timestamp.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"
    with open(APP_LOG, "a", encoding="utf-8") as f:
        f.write(line)
