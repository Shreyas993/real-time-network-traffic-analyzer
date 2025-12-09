# 🖧 Real-Time Network Traffic Analyzer

An advanced Python-based network traffic monitoring tool for Windows, capturing, analyzing, and visualizing live network traffic. Implements packet capture using Scapy with support for TCP, UDP, ICMP, ARP, and custom BPF filters, detailed packet analysis, color-coded CLI output using Colorama, a live GUI dashboard using Tkinter and Matplotlib, CSV logging, and visualizations of protocol distribution and top source IPs. Ideal for network monitoring, cybersecurity analysis, and portfolio demonstration.

## Features

Capture packets with configurable filters (TCP, UDP, ICMP, ARP, or custom BPF)

Analyze packet details: source/destination IP, protocol, ports, packet length

Classify packets into TCP, UDP, ICMP, ARP, or OTHER

Detect large packets (>1500 bytes) and display alerts

Live, color-coded CLI dashboard showing total packets, protocol counts, top source IPs, runtime, and alerts

Real-time GUI dashboard displaying charts for protocol distribution and top source IPs

Logs all captured packets into timestamped CSV files in logs/

Saves visualization charts to visuals/

GUI Quit button for safe exit without force-closing the window

Modular, structured, and well-commented code—excellent for learning and portfolio use

## Installation

### Clone the repository:
git clone https://github.com/Shreyas993/real-time-network-traffic-analyzer.git
cd real_time_network_traffic_analyzer

### Create and activate a virtual environment (Windows PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

## Install dependencies:
pip install -r requirements.txt
Dependencies include: scapy, matplotlib, colorama (Tkinter is built-in on Windows).

## Usage

Run the tool:
python main.py

Choose a capture filter (TCP, UDP, ICMP, ARP, or custom BPF)

Enter the number of packets to capture (default: 30)

The CLI dashboard will live-update:

Total packets captured

Protocol counts

Top source IPs

Runtime

Alerts if large packets are detected

The GUI dashboard will display real-time charts

Use the Quit button for safe exit

Logs and visuals are automatically saved:

Packet CSV logs → logs/

Protocol and IP charts → visuals/

## Example Output

=== Real-Time Network Traffic Analyzer ===
Total packets captured: 20
Analyzing packets...
{'src_ip': '192.168.0.10', 'dst_ip': '192.168.0.5', 'protocol': 'TCP', 'src_port': 31676, 'dst_port': 8009, 'length': 171}
{'src_ip': '104.18.39.21', 'dst_ip': '192.168.0.10', 'protocol': 'TCP', 'src_port': 443, 'dst_port': 49668, 'length': 82}
Packet analysis complete.
[+] Log saved: logs/capture_2025-12-09_20-11-52.csv
[+] Protocol distribution chart saved: visuals/protocol_distribution.png
[+] Top source IPs chart saved: visuals/top_source_ips.png

## Folder Structure
real_time_network_traffic_analyzer/
├─ capture/                # Packet capture modules (sniffer.py)
├─ analysis/               # Packet analysis modules (parser.py)
├─ stats/                  # CLI stats and dashboard backend (dashboard.py)
├─ gui/                    # Tkinter GUI modules (dashboard_gui.py)
├─ visuals/                # Saved charts for protocol distribution and top IPs
├─ logs/                   # Captured packet CSV logs
├─ utils/                  # Logger and utility functions (logger.py)
├─ requirements.txt        # Python dependencies for running the project
├─ main.py                 # Main executable script
└─ README.md               # Project documentation

## Technical Details

Packet Capture: Scapy (supports TCP, UDP, ICMP, ARP, and custom BPF filters)

Visualization: Matplotlib for charts; Tkinter for real-time GUI dashboard

CLI: Colorama for color-coded professional output

Storage: CSV logs + PNG charts

Alerts: Large-packet detection, anomaly indicators

Future Enhancements

Real-time alerts via email/SMS for abnormal traffic

Geolocation mapping of IP addresses in the GUI

Search/filter panel for protocols or IPs

Cross-platform compatibility (Windows + Linux)

## References

Scapy Documentation — https://scapy.readthedocs.io/

Matplotlib Documentation — https://matplotlib.org/stable/contents.html

Tkinter Documentation — https://docs.python.org/3/library/tkinter.html

## Author

Shreyas Ramkumar — Master’s student in Cybersecurity at RMIT University
GitHub: https://github.com/Shreyas993
