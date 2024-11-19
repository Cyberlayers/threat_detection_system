import scapy.all as scapy

def detect_suspicious_packets(packet):
    """
    Detect and log all packets for debugging.
    Add specific detection logic as needed.
    """
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Packet detected: {packet.summary()}")  # Log all detected packets
        # Example of detecting suspicious packets based on IP address
        if ip_src == "192.168.1.1" or ip_dst == "192.168.1.1":
            print(f"Suspicious packet detected! Source: {ip_src}, Destination: {ip_dst}")

def sniff_packets(interface="eth0"):
    """
    Sniffs packets on the specified network interface.
    """
    print(f"Sniffing packets on interface {interface}...")
    try:
        scapy.sniff(iface=interface, prn=detect_suspicious_packets, store=False)
    except PermissionError:
        print("Error: Insufficient permissions. Please run the script with sudo.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    try:
        # Prompt user to enter the network interface
        interface = input("Enter the network interface to monitor (e.g., eth0): ").strip()
        if not interface:
            raise ValueError("No interface provided. Please specify a valid network interface.")
        sniff_packets(interface)
    except ValueError as ve:
        print(ve)
    except KeyboardInterrupt:
        print("\nExiting... Sniffing stopped.")
with open("detected_packets.log", "a") as log_file:
    log_file.write(f"Packet detected: {packet.summary()}\n")

