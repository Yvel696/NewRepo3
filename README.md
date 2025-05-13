# 🦈 SharkySniffer: Python Packet Sniffer with GUI and Anomaly Detection

**SharkySniffer** is a lightweight Python-based packet sniffer inspired by Wireshark. It provides real-time packet capture, a GUI interface for live viewing, and basic anomaly detection to help identify suspicious network activity.

## 🚀 Features

- 🖥 Real-time packet sniffing (IP-based)
- 📊 GUI built with Tkinter to view live traffic
- 🧠 Anomaly detection engine:
  - Port scan detection
  - Telnet and other suspicious port monitoring
  - Packet burst detection (possible DoS)
- 💾 Option to expand into PCAP/CSV logging
- 🎯 CLI and GUI modes available

---


## 🧰 Requirements

### 📦 Python Libraries

Install required libraries using pip:

```bash
pip install scapy
