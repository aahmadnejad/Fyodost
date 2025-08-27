import socket
import re
import netifaces
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, ARP, Ether, srp
import threading
import time
from prettytable import PrettyTable

def validate_mac(mac_address):
    if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address):
        return True
    return False

def validate_ip(ip_address):
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def get_interface_info():
    return get_if_list()

def print_banner():
    print("\033[5;91m" + r"""
    ███████╗██╗   ██╗ ██████╗ ██████╗  ██████╗ ███████╗████████╗
    ██╔════╝╚██╗ ██╔╝██╔═══██╗██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
    █████╗   ╚████╔╝ ██║   ██║██║  ██║██║   ██║███████╗   ██║   
    ██╔══╝    ╚██╔╝  ██║   ██║██║  ██║██║   ██║╚════██║   ██║   
    ██║        ██║   ╚██████╔╝██████╔╝╚██████╔╝███████║   ██║   
    ╚═╝        ╚═╝    ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   
""" + "\033[0m"+ "\033[31m" + r"""
         _____                                _______
       ,/_    ``-._                          /       \
      ,|:          `'-..__               ___|         |_
     ,|:_                 ``'''-----''''`_::~-.......-'~\
    ,|:_                                 _:    . ' .    :
    |:_                                  _:  .   '   .  |
    |:_                                  _:  '   .   '  |
    |:_                                  _:    ' . '    :
    |:_                    __,,...---...,,:_,.-'''''-.,_/
    |:_              _,.-``                 |         |
    |:_           ,-`                       |         |
    |:_         ,`                          |         |
    `|:_      ,'                            |         |
     |:_     /                              |         |
     `|:_   /                               |         |
      `|:_ :                                |         |
        \: |                                |         |
         \:|                                |         |
          ~
""" +"\033[0m"+ "\033[1m"+"""
Fyodost — Your all-in-one Layer 2 offensive arsenal, complete control over the Layer 2 battlefield.
    """+"\033[0m")

def scan_network(interface, timeout=2, include_self=True):
    """
    Scan the network for devices and return a list of (ip, mac) tuples
    """
    try:
        ip = get_if_addr(interface)
        mac = get_if_hwaddr(interface)
        
        ip_parts = ip.split('.')
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        print(f"[SCAN] Scanning network {network} on interface {interface}...")
        
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False, iface=interface)[0]
        
        devices = []
        for element in answered_list:
            device_ip = element[1].psrc
            device_mac = element[1].hwsrc
            vendor = get_mac_vendor(device_mac)
            
            if not include_self and device_mac == mac:
                continue
                
            devices.append({
                'ip': device_ip,
                'mac': device_mac,
                'vendor': vendor,
                'is_self': device_mac == mac
            })
        
        return devices
        
    except Exception as e:
        print(f"[SCAN] Error scanning network: {e}")
        return []

def display_devices_table(devices, interface=None):
    """
    Display a table of network devices with pretty formatting
    """
    if not devices:
        print("No devices found on the network")
        return
    
    table = PrettyTable()
    table.field_names = ["IP Address", "MAC Address", "Vendor", "Self"]
    table.align["IP Address"] = "l"
    table.align["MAC Address"] = "l"
    table.align["Vendor"] = "l"
    
    for device in devices:
        is_self = device['is_self']
        ip = device['ip']
        mac = device['mac']
        vendor = device['vendor'][:20] + "..." if len(device['vendor']) > 20 else device['vendor']
        
        if is_self:
            ip = f"\033[92m{ip}\033[0m" 
            mac = f"\033[92m{mac}\033[0m"  
            vendor = f"\033[92m{vendor}\033[0m"  
        
        table.add_row([ip, mac, vendor, "✓" if is_self else ""])
    
    if interface:
        print(f"\nDevices on network (Interface: {interface}):")
    else:
        print("\nDevices on network:")
    
    print(table)
    print(f"Total devices found: {len(devices)}")

def get_mac_vendor(mac_address):
    """Get vendor from MAC address using OUI database"""
    oui_db = {
        "00:00:0C": "Cisco",
        "00:1B:21": "HP",
        "00:1C:B3": "Dell",
        "00:03:93": "Apple",
        "00:15:5D": "Microsoft",
        "00:1A:11": "Google",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:0C:29": "VMware",
        "00:1C:42": "Parallels",
        "52:54:00": "QEMU",
        "AA:BB:CC": "Custom/Test",
        "00:16:3E": "Xen",
        "02:00:4C": "Docker",
    }
    
    try:
        oui = mac_address[:8].upper()
        return oui_db.get(oui, "Unknown")
    except:
        return "Unknown"

def get_random_mac(vendor=None):
    """Generate a random MAC address, optionally with specific vendor OUI"""
    vendor_ouis = {
        "cisco": "00:00:0C",
        "hp": "00:1B:21", 
        "dell": "00:1C:B3",
        "apple": "00:03:93",
        "microsoft": "00:15:5D",
        "google": "00:1A:11",
        "random": None
    }
    
    if vendor and vendor.lower() in vendor_ouis:
        oui = vendor_ouis[vendor.lower()]
        if oui:
            import random
            nic = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
            return f"{oui}:{nic}"
    
    from scapy.all import RandMAC
    return str(RandMAC())

def get_random_ip(network=None):
    """Generate a random IP address, optionally within a specific network"""
    import random
    import ipaddress
    
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
            return str(random.choice(list(net.hosts())))
        except:
            pass
    
    private_networks = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16"
    ]
    
    network = random.choice(private_networks)
    net = ipaddress.ip_network(network, strict=False)
    return str(random.choice(list(net.hosts())))