# 🖧 Real-Time Network Traffic Analyzer
An advanced Python-based network traffic monitoring tool for Windows, capturing, analyzing, and visualizing live network traffic. Implements packet capture using Scapy with support for TCP, UDP, ICMP, ARP, or custom BPF filters, detailed packet analysis, color-coded CLI output using Colorama, live GUI dashboard using Tkinter and Matplotlib, CSV logging, and visualization of protocol distribution and top source IPs. Ideal for network monitoring, cybersecurity analysis, and portfolio demonstration.

## Features
- Capture packets with configurable filters (TCP, UDP, ICMP, ARP, or custom)
- Analyze packet details: source/destination IP, protocol, ports, packet length
- Classify packets into TCP, UDP, ICMP, ARP, or OTHER
- Detect large packets (>1500 bytes) for alerts
- Live, color-coded CLI dashboard showing total packets, protocol counts, top source IPs, runtime, and alerts
- Real-time GUI dashboard displaying charts for protocol distribution and top source IPs
- Logs all captured packets into timestamped CSV files in `logs/`
- Saves visual charts as images in `visuals/`
- Quit button in GUI for safe exit
- Modular and well-commented code for educational and portfolio use

## Installation
1. Clone the repository:  
`git clone https://github.com/<your-username>/network_traffic_analyzer.git`  
`cd network_traffic_analyzer`
2. Create and activate a virtual environment (Windows PowerShell):  
`python -m venv venv`  
`.\venv\Scripts\Activate.ps1`
3. Install dependencies:  
`pip install -r requirements.txt`  
Dependencies include: `scapy`, `matplotlib`, `colorama`, `tkinter` (built-in)

## Usage
1. Run the tool:  
`python main.py`
2. Choose a capture filter: TCP, UDP, ICMP, ARP, or custom BPF
3. Enter packet count to capture (default 30)
4. CLI will display live stats: total packets, protocol counts, top source IPs, runtime, and alerts
5. GUI dashboard will show live charts with color-coded labels and alerts
6. Use the Quit button in GUI to safely exit
7. Logs and visuals saved automatically:  
- Packet data CSVs: `logs/`  
- Chart images: `visuals/`

## Example
=== Real-Time Network Traffic Analyzer ===
Total packets captured: 20
Analyzing packets...
{'src_ip': '192.168.68.103', 'dst_ip': '192.168.68.105', 'protocol': 'TCP', 'src_port': 31676, 'dst_port': 8009, 'length': 171}
{'src_ip': '104.18.39.21', 'dst_ip': '192.168.68.103', 'protocol': 'TCP', 'src_port': 443, 'dst_port': 49668, 'length': 82}
...
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
- Packet Capture: Scapy (supports TCP, UDP, ICMP, ARP, custom BPF filters)
- Visualization: Matplotlib for charts, Tkinter for GUI dashboard
- CLI: Colorama for color-coded, professional interface
- Logging: CSV files for packet capture data, image files for charts
- Alerts: Detection of large packets and traffic anomalies

## Future Enhancements
- Real-time alerts via email or SMS for abnormal traffic
- Geolocation mapping for IP addresses in the GUI dashboard
- Filtering and search functionality in GUI for specific protocols or IPs
- Cross-platform compatibility for Windows and Linux

## References
- Scapy Documentation: https://scapy.readthedocs.io/  
- Matplotlib Documentation: https://matplotlib.org/stable/contents.html  
- Tkinter Documentation: https://docs.python.org/3/library/tkinter.html

## Author
Shreyas Ramkumar — Master’s student in Cybersecurity at RMIT University  
GitHub: https://github.com/Shreyas993