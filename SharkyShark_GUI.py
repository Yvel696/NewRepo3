import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
from datetime import datetime
from collections import defaultdict
import time

is_sniffing = False
connection_tracker = defaultdict(set)
packet_counts = defaultdict(int)
burst_threshold = 50  # packets per 5 seconds from same source

def detect_anomalies(packet):
    if not packet.haslayer("IP"):
        return

    src_ip = packet[0][1].src
    dst_port = packet[0][2].dport if hasattr(packet[0][2], 'dport') else None
    proto = packet[0][1].name

    # 1. Port scanning detection
    if dst_port:
        connection_tracker[src_ip].add(dst_port)
        if len(connection_tracker[src_ip]) > 20:
            print(f"⚠️ Possible port scan from {src_ip}! More than 20 ports hit.")
    
    # 2. Suspicious ports (e.g., Telnet)
    if dst_port in [23, 2323]:
        print(f"🚨 Suspicious traffic: {src_ip} tried to use Telnet on port {dst_port}")

    # 3. Packet burst detection
    now = int(time.time())
    packet_counts[(src_ip, now)] += 1
    burst = sum([packet_counts[(src_ip, t)] for t in range(now - 5, now + 1)])
    if burst > burst_threshold:
        print(f"🚨 Possible DoS activity: {src_ip} sent {burst} packets in 5 seconds")

def handle_packet(packet):
    if not packet.haslayer("IP"):
        return

    detect_anomalies(packet)

    timestamp = datetime.now().strftime('%H:%M:%S')
    proto = packet[0][1].name
    src = packet[0][1].src
    dst = packet[0][1].dst

    tree.insert("", "end", values=(timestamp, proto, src, dst))

def start_sniffing():
    global is_sniffing
    is_sniffing = True

    def sniff_thread():
        sniff(filter="ip", prn=handle_packet, stop_filter=lambda x: not is_sniffing)

    thread = threading.Thread(target=sniff_thread)
    thread.daemon = True
    thread.start()

def stop_sniffing():
    global is_sniffing
    is_sniffing = False

# GUI Setup
root = tk.Tk()
root.title("SharkyShark + IDS")
root.geometry("800x400")

frame = tk.Frame(root)
frame.pack(pady=10)

start_btn = tk.Button(frame, text="Start Capture", command=start_sniffing)
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = tk.Button(frame, text="Stop Capture", command=stop_sniffing)
stop_btn.pack(side=tk.LEFT, padx=5)

columns = ("Timestamp", "Protocol", "Source IP", "Destination IP")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="center")

tree.pack(expand=True, fill="both", pady=10)

root.mainloop()
