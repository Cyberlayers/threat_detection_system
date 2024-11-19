# Threat Detection System

The **Threat Detection System** is a Python-based cybersecurity tool designed to monitor network traffic in real time. It logs and analyzes packets for suspicious activities, helping security professionals detect unauthorized connections, potential threats, or malicious packets.

---

## Features
- Monitors network packets on a specified interface.
- Logs all detected packets for further analysis.
- Detects suspicious activity based on IP addresses or custom rules.
- Lightweight and easy to customize.

---

## Requirements
- **Python 3**: Ensure Python 3 is installed on your system.
- **Scapy Library**: A Python library for network packet manipulation and analysis.

---

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Cyberlayers/threat_detection_system.git
   cd threat_detection_system
2. **Install the Required Library**:
   sudo apt update
   sudo apt install python3-scapy
 
---

## Usage Instructions
1. **Run the script with elevated privileges**:    
   sudo python3 threat_detection_system.py
2. Enter the network interface to monitor (e.g., eth0 or wlan0).
3. Monitor real-time output in the terminal or view logged packets in the file detected_packets.log.
4. Log File Example:

Packet detected: Ether / IP / TCP 192.168.1.10:443 > 10.0.0.5:80
Suspicious packet detected! Source: 192.168.1.10, Destination: 10.0.0.5

## Example Output
In the terminal:

Enter the network interface to monitor (e.g., eth0): eth0
Sniffing packets on interface eth0...
Packet detected: Ether / IP / TCP 192.168.44.128:51098 > 34.90.139.139:30010 A
Packet detected: Ether / IP / TCP 34.90.139.139:30010 > 192.168.44.128:51098 A / Padding

In the log file (detected_packets.log):

Packet detected: Ether / IP / TCP 192.168.44.128:51098 > 34.90.139.139:30010
Suspicious packet detected! Source: 192.168.44.128, Destination: 34.90.139.139

## Limitations
Requires elevated privileges (sudo) to sniff packets.
Custom detection logic needs to be implemented for specific use cases.
Designed for authorized use only on networks you have permission to monitor.

## How It Works
The tool uses the Scapy library to sniff network packets in real-time.
Detected packets are:
Printed to the terminal for immediate feedback.
Logged in the detected_packets.log file for offline analysis.
Detection criteria can be customized in the detect_suspicious_packets() function.
 
## Customization
To modify the detection logic:

Open the script:
bash
Copy code
nano threat_detection_system.py
Edit the detect_suspicious_packets() function:
python
Copy code
if packet.haslayer(scapy.IP):
    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst
    if "192.168.1.100" in (ip_src, ip_dst):
        print(f"Suspicious packet detected! {packet.summary()}")

## Disclaimer
This tool is intended for educational purposes and authorized network security testing only. Unauthorized monitoring of networks is illegal and unethical. The author is not responsible for misuse of this tool.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

