from scapy.all import sniff, Raw, wrpcap
from datetime import datetime
import csv

captured_packets = []
csv_rows = []

def handle_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src = packet[0][1].src if packet.haslayer("IP") else "N/A"
    dst = packet[0][1].dst if packet.haslayer("IP") else "N/A"
    proto = packet[0][1].name

    print("=" * 80)
    print(f"🕒 {timestamp} | {proto} | {src} → {dst}")
    print(packet.summary())

    # Store full packet (for PCAP)
    captured_packets.append(packet)

    # Store summary row (for CSV)
    csv_rows.append([timestamp, proto, src, dst])

if __name__ == "__main__":
    print("📡 Capturing packets and saving to log files...\n(Press Ctrl+C to stop)\n")

    try:
        sniff(filter="ip", prn=handle_packet, store=False)

    except KeyboardInterrupt:
        # Save to PCAP
        pcap_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(pcap_filename, captured_packets)
        print(f"\n💾 Saved PCAP log to {pcap_filename}")

        # Save to CSV
        csv_filename = pcap_filename.replace(".pcap", ".csv")
        with open(csv_filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Protocol", "Source", "Destination"])
            writer.writerows(csv_rows)
        print(f"💾 Saved CSV log to {csv_filename}")
