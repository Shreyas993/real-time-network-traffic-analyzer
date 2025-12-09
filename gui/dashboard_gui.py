import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from stats.stats_manager import StatsManager
import threading
import time

# Color mapping for protocols
PROTOCOL_COLORS = {
    "TCP": "green",
    "UDP": "blue",
    "ICMP": "orange",
    "ARP": "purple",
    "OTHER": "gray"
}

# Thresholds for anomaly detection
LARGE_PACKET_THRESHOLD = 1500
TOP_IP_ALERT_THRESHOLD = 20  # more than 20 packets from same IP
PROTO_SPIKE_THRESHOLD = 30   # more than 30 packets in same protocol


class CreateToolTip:
    """
    Create a tooltip for a given widget
    """
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.showtip()

    def leave(self, event=None):
        self.hidetip()

    def showtip(self):
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#ffffe0", relief='solid', borderwidth=1,
                         font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()


class PacketDashboard:
    def __init__(self, stats_manager: StatsManager):
        self.stats_manager = stats_manager
        self.root = tk.Tk()
        self.root.title("Real-Time Network Traffic Analyzer - Live Dashboard")
        self.root.geometry("950x700")

        # Matplotlib figures
        self.fig_proto, self.ax_proto = plt.subplots(figsize=(4, 3))
        self.fig_ip, self.ax_ip = plt.subplots(figsize=(4, 3))

        # Embed protocol chart
        self.canvas_proto = FigureCanvasTkAgg(self.fig_proto, master=self.root)
        self.canvas_proto.get_tk_widget().grid(row=0, column=0, padx=10, pady=10)

        # Embed IP chart
        self.canvas_ip = FigureCanvasTkAgg(self.fig_ip, master=self.root)
        self.canvas_ip.get_tk_widget().grid(row=0, column=1, padx=10, pady=10)

        # Stats labels frame
        self.stats_frame = tk.Frame(self.root)
        self.stats_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="w")

        # Total and large packets labels
        self.label_total = tk.Label(self.stats_frame, text="Total Packets: 0", font=("Arial", 12))
        self.label_total.grid(row=0, column=0, sticky="w", padx=10)

        self.label_large = tk.Label(self.stats_frame, text="Large Packets (>1500 bytes): 0", font=("Arial", 12))
        self.label_large.grid(row=0, column=1, sticky="w", padx=10)

        # Protocol labels (color-coded)
        self.proto_labels = {}
        col = 0
        for proto, color in PROTOCOL_COLORS.items():
            lbl = tk.Label(self.stats_frame, text=f"{proto}: 0", fg=color, font=("Arial", 12, "bold"))
            lbl.grid(row=1, column=col, padx=10, pady=5)
            self.proto_labels[proto] = lbl
            col += 1

        # Attach tooltips to protocol labels
        for proto, lbl in self.proto_labels.items():
            CreateToolTip(lbl, text=f"{proto} packets count (updates live)")

        # Anomaly label
        self.label_alert = tk.Label(self.stats_frame, text="", fg="red", font=("Arial", 12, "bold"))
        self.label_alert.grid(row=2, column=0, columnspan=5, pady=5)

        # Quit button
        self.quit_button = tk.Button(self.stats_frame, text="Quit", command=self.stop_dashboard, bg="red", fg="white")
        self.quit_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Start update thread
        self.running = True
        threading.Thread(target=self.update_dashboard, daemon=True).start()
        self.root.mainloop()

    def stop_dashboard(self):
        """Safely stop the dashboard"""
        self.running = False
        self.root.destroy()
        print("Dashboard closed.")

    def update_dashboard(self):
        while self.running:
            stats = self.stats_manager.get_stats()

            # Update total and large packets
            self.label_total.config(text=f"Total Packets: {stats['total_packets']}")
            self.label_large.config(text=f"Large Packets (>1500 bytes): {stats['large_packets']}")
            if stats['large_packets'] > 0:
                self.label_large.config(fg="red")
            else:
                self.label_large.config(fg="black")

            # Update protocol labels and detect protocol spikes
            spike_alerts = []
            for proto, lbl in self.proto_labels.items():
                count = stats['protocol_counts'].get(proto, 0)
                lbl.config(text=f"{proto}: {count}")
                if count > PROTO_SPIKE_THRESHOLD:
                    spike_alerts.append(f"{proto} spike: {count}")

            # Detect top IP anomalies
            ip_alerts = []
            for ip, count in stats['top_sources'].items():
                if count > TOP_IP_ALERT_THRESHOLD:
                    ip_alerts.append(f"High traffic from {ip}: {count} packets")

            # Display anomalies
            alerts = spike_alerts + ip_alerts
            self.label_alert.config(text=" | ".join(alerts) if alerts else "")

            # Update protocol bar chart
            self.ax_proto.clear()
            protocols = stats['protocol_counts'].keys()
            counts = stats['protocol_counts'].values()
            colors = [PROTOCOL_COLORS.get(p, "gray") for p in protocols]
            self.ax_proto.bar(protocols, counts, color=colors)
            self.ax_proto.set_title("Protocol Counts")
            self.ax_proto.set_ylabel("Packet Count")
            self.ax_proto.set_ylim(0, max(counts) + 5 if counts else 10)
            self.canvas_proto.draw()

            # Update top source IPs pie chart
            self.ax_ip.clear()
            top_ips = stats['top_sources']
            if top_ips:
                self.ax_ip.pie(top_ips.values(), labels=top_ips.keys(), autopct='%1.1f%%', startangle=140)
                self.ax_ip.set_title("Top Source IPs")
            self.canvas_ip.draw()

            time.sleep(1)
