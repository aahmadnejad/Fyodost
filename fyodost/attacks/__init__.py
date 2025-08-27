from . import cam_flood
from . import cdp_flood
from . import dhcp_starvation
from . import dhcp_spoofing
from . import double_vlan
from . import impersonation
from . import switch_spoofing
from . import stp_attack
from . import vlan_hopping
from . import arp_poisoning
from . import dhcp_rogue
from . import mac_spoofing
from . import lldp_attack
from . import pvlan_attack
from . import mstp_attack

ATTACK_MODULES = {
    "cam_flood": cam_flood,
    "cdp_flood": cdp_flood,
    "dhcp_starvation": dhcp_starvation,
    "dhcp_spoofing": dhcp_spoofing,
    "double_vlan": double_vlan,
    "impersonation": impersonation,
    "switch_spoofing": switch_spoofing,
    "stp_attack": stp_attack,
    "vlan_hopping": vlan_hopping,
    "arp_poisoning": arp_poisoning,
    "dhcp_rogue": dhcp_rogue,
    "mac_spoofing": mac_spoofing,
    "lldp_attack": lldp_attack,
    "pvlan_attack": pvlan_attack,
    "mstp_attack": mstp_attack,
}