from scapy.all import *
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

captured_packets = []

def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(DNS):
        return "DNS"
    else:
        return "OTHER"

def packet_callback(packet):

    captured_packets.append(packet)

    print(Fore.CYAN + "="*80)

    print(Fore.YELLOW + f"Time : {datetime.now()}")

    if packet.haslayer(Ether):
        print(Fore.GREEN +
              f"MAC : {packet[Ether].src}  -->  {packet[Ether].dst}")

    if packet.haslayer(IP):

        ip = packet[IP]

        print(Fore.GREEN +
              f"IP  : {ip.src}  -->  {ip.dst}")

        print(Fore.MAGENTA +
              f"TTL : {ip.ttl}")

        print(Fore.BLUE +
              f"Protocol : {protocol_name(packet)}")

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        print(Fore.YELLOW +
              f"TCP Ports : {tcp.sport} --> {tcp.dport}")

        print(Fore.YELLOW +
              f"Flags : {tcp.flags}")

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        print(Fore.YELLOW +
              f"UDP Ports : {udp.sport} --> {udp.dport}")

    elif packet.haslayer(ICMP):

        icmp = packet[ICMP]

        print(Fore.YELLOW +
              f"ICMP Type : {icmp.type}")

    print(Fore.WHITE +
          f"Packet Size : {len(packet)} bytes")

    if packet.haslayer(Raw):

        payload = bytes(packet[Raw].load)

        print(Fore.RED + "\nASCII Payload")
        print(payload[:150])

        print(Fore.RED + "\nHEX Payload")
        print(payload.hex()[:300])

    print(Style.RESET_ALL)


try:

    print(Fore.CYAN + "Starting Advanced Packet Sniffer...")
    print(Fore.CYAN + "Press Ctrl+C to Stop\n")

    sniff(prn=packet_callback,
          store=False)

except KeyboardInterrupt:

    print("\nSaving packets...")

    wrpcap("capture.pcap", captured_packets)

    print("Packets saved to capture.pcap")
