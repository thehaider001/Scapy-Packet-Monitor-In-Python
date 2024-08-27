from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[+] Protocol: TCP | Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")
            print(f"[+] Payload: {bytes(tcp_layer.payload)}")
        
        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[+] Protocol: UDP | Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}")
            print(f"[+] Payload: {bytes(udp_layer.payload)}")

def main():
    # Start sniffing
    print("Starting packet sniffing...")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
