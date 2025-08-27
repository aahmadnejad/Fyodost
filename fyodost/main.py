#!/usr/bin/env python3
"""
FYODOST - Layer 2 Attack Research Toolkit
For academic research purposes only - MSc Thesis IDS Dataset Generation
"""

import argparse
import sys
import time
import random
import importlib
import os
from pathlib import Path

# Add the current directory to path to find utils
sys.path.insert(0, str(Path(__file__).parent))

try:
    from fyodost.utils.helpers import validate_mac, validate_ip, get_interface_info, print_banner, scan_network, display_devices_table
    from fyodost.utils.quotes import quotes
except ImportError:
    # Fallback for direct execution
    from utils.helpers import validate_mac, validate_ip, get_interface_info, print_banner, scan_network, display_devices_table
    from utils.quotes import quotes

def list_attacks():
    """List all available attacks"""
    attack_files = Path("attacks").glob("*.py")
    attacks = [f.stem for f in attack_files if not f.name.startswith("__")]
    
    # Categorize attacks
    categories = {
        "Flooding Attacks": ["cam_flood", "cdp_flood", "dhcp_starvation"],
        "Spoofing Attacks": ["arp_poisoning", "dhcp_spoofing", "mac_spoofing", "impersonation", "dhcp_rogue"],
        "Protocol Attacks": ["stp_attack", "mstp_attack", "lldp_attack"],
        "VLAN Attacks": ["double_vlan", "vlan_hopping", "pvlan_attack"],
        "Switch Attacks": ["switch_spoofing", "cdp_flood"]
    }
    
    print("Available attacks by category:")
    for category, attack_list in categories.items():
        print(f"\n{category}:")
        for attack in attack_list:
            if attack in attacks:
                print(f"  {attack.replace('_', ' ').title()}")
    
    return attacks

def execute_attack(attack_name, args):
    """Dynamically import and execute the requested attack"""
    try:
        # Import the attack module
        module = importlib.import_module(f"attacks.{attack_name}")
        
        # Check if the module has an execute function
        if hasattr(module, 'execute'):
            return module.execute(args)
        else:
            print(f"[-] Attack module {attack_name} doesn't have an execute function")
            return False
            
    except ImportError as e:
        print(f"[-] Could not import attack {attack_name}: {e}")
        return False
    except Exception as e:
        print(f"[-] Error executing attack {attack_name}: {e}")
        import traceback
        traceback.print_exc()
        return False

def select_random_target(interface, exclude_self=True):
    """
    Select a random target from the network
    """
    devices = scan_network(interface, include_self=not exclude_self)
    
    if not devices:
        print("[-] No devices found on the network for target selection")
        return None, None
    
    # Filter out our own device if needed
    if exclude_self:
        target_devices = [d for d in devices if not d['is_self']]
    else:
        target_devices = devices
    
    if not target_devices:
        print("[-] No target devices available (only our own device found)")
        return None, None
    
    # Select a random target
    target = random.choice(target_devices)
    return target['ip'], target['mac']

def get_attack_arguments(attack_name):
    """Get attack-specific arguments from the attack module"""
    try:
        module = importlib.import_module(f"attacks.{attack_name}")
        if hasattr(module, 'add_arguments'):
            return module.add_arguments
        return None
    except ImportError:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="FYODOST - Layer 2 Attack Research Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all available attacks
  sudo fyodost --list-attacks
  
  # CDP flood attack with custom interval
  sudo fyodost --attack cdp_flood --interface eth0 --count 2000 --interval 0.05
  
  # DHCP starvation attack
  sudo fyodost --attack dhcp_starvation --interface eth0 --persistent
  
  # ARP poisoning with PCAP capture
  sudo fyodost --attack arp_poisoning --interface eth0 --target-ip 192.168.1.100 --gateway-ip 192.168.1.1 --pcap
  
  # Network scan
  sudo fyodost --scan --interface eth0
        """
    )
    
    parser.add_argument("--attack", help="Specific attack to execute")
    parser.add_argument("--list-attacks", action="store_true", help="List all available attacks")
    parser.add_argument("--scan", "-s", action="store_true", help="Scan network and display devices")
    
    parser.add_argument("--interface", "-i", help="Network interface to use")
    parser.add_argument("--target-ip", "-ti", help="Target IP address")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--gateway-ip", "-gi", help="Gateway IP address")
    parser.add_argument("--gateway-mac", "-gm", help="Gateway MAC address")
    parser.add_argument("--count", "-c", type=int, help="Number of packets to send")
    parser.add_argument("--duration", "-d", type=int, help="Attack duration in seconds")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--pcap", nargs="?", const="default", 
                       help="Enable PCAP capture. Specify path or use default: ~/Fyodost/")
    
    args, unknown = parser.parse_known_args()
    
    if args.attack:
        add_arguments_func = get_attack_arguments(args.attack)
        if add_arguments_func:
            add_arguments_func(parser)
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.list_attacks:
        list_attacks()
        return
    
    if args.scan:
        if not args.interface:
            print("[-] Interface is required for network scan")
            return
        
        devices = scan_network(args.interface)
        display_devices_table(devices, args.interface)
        return
    
    if os.geteuid() != 0:
        print("[-] This tool requires root privileges. Run with sudo.")
        sys.exit(1)
    
    if args.interface and args.interface not in get_interface_info():
        print(f"[-] Interface {args.interface} not found or not available")
        print("Available interfaces:")
        for iface in get_interface_info():
            print(f"  {iface}")
        return
    
    if args.target_mac and not validate_mac(args.target_mac):
        print("[-] Invalid target MAC address format")
        return
        
    if args.gateway_mac and not validate_mac(args.gateway_mac):
        print("[-] Invalid gateway MAC address format")
        return
    
    if args.target_ip and not validate_ip(args.target_ip):
        print("[-] Invalid target IP address format")
        return
        
    if args.gateway_ip and not validate_ip(args.gateway_ip):
        print("[-] Invalid gateway IP address format")
        return
    
    if args.attack:
        print(f"[+] Executing {args.attack.replace('_', ' ').title()} attack")
        print(f"[+] Interface: {args.interface}")
        
        target_dependent_attacks = [
            'arp_poisoning', 'impersonation', 'pvlan_attack', 
            'mac_spoofing', 'vlan_hopping'
        ]
        
        if args.attack in target_dependent_attacks and not args.target_ip and not args.target_mac:
            print("[+] No target specified, selecting random target from network...")
            target_ip, target_mac = select_random_target(args.interface)
            
            if target_ip and target_mac:
                args.target_ip = target_ip
                args.target_mac = target_mac
                print(f"[+] Selected target: {target_ip} ({target_mac})")
            else:
                print("[-] Could not find a suitable target. Please specify --target-ip or --target-mac.")
                return
        
        if args.attack in ['arp_poisoning'] and not args.gateway_ip:
            print("[+] No gateway specified, trying to detect default gateway...")
            try:
                import netifaces
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET][0]
                args.gateway_ip = default_gateway
                print(f"[+] Detected gateway: {default_gateway}")
            except:
                print("[-] Could not detect default gateway. Please specify --gateway-ip.")
                return
        
        if args.target_ip:
            print(f"[+] Target IP: {args.target_ip}")
        if args.target_mac:
            print(f"[+] Target MAC: {args.target_mac}")
        if args.gateway_ip:
            print(f"[+] Gateway IP: {args.gateway_ip}")
        if args.gateway_mac:
            print(f"[+] Gateway MAC: {args.gateway_mac}")
        if args.count:
            print(f"[+] Packet count: {args.count}")
        if args.duration:
            print(f"[+] Duration: {args.duration}s")
            
        print("-" * 50)
        
        success = execute_attack(args.attack, args)
        
        if success:
            print(f"\n[+] {args.attack.replace('_', ' ').title()} attack completed successfully")
        else:
            print(f"\n[-] {args.attack.replace('_', ' ').Title()} attack failed")
    else:
        print("[-] No attack specified. Use --attack or --list-attacks")
        parser.print_help()
    
    print(f"\n{30*'='}")
    print(f"\033[3;95m\"{(c := random.choice(quotes))[0]}\" __ {c[1]}\033[0m")

if __name__ == "__main__":
    main()