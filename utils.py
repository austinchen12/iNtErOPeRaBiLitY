from ipaddress import IPv4Address, ip_network, ip_address
from datetime import datetime

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

TYPE_IPV4           = 0x800
TYPE_ARP            = 0x806
TYPE_CPU_METADATA   = 0x80a
TYPE_OSPF           = 89

HW_TYPE_ETHERNET    = 0x1

MASK_24 = 0xFFFFFF00
MASK_32 = 0xFFFFFFFF

TYPE_OSPF_HELLO = 0x1
TYPE_OSPF_LSU = 0x4
ALLSPFRouters = "224.0.0.5"

BIRTHDAY = datetime(2002, 2, 28)

def create_subnet(ip, mask_hex):
    # to CIDR
    ip = int(IPv4Address(ip))
    network_int = ip & mask_hex
    mask_length = bin(mask_hex).count('1')
    return f"{IPv4Address(network_int)}/{mask_length}"

def add_mask_size(subnet, maskhex):
    # appends /size
    prefix_size = bin(maskhex).count('1')
    return '%s/%d' % (subnet, prefix_size)

def get_subnet_mask(subnet):
    # gets mask hex
    prefix = int(subnet.split('/')[1])
    return (2 ** prefix - 1) << (32 - prefix)

def apply_mask(subnet, mask):
    if "/" in subnet:
        subnet = subnet.split("/")[0]
    subnet = int(IPv4Address(subnet))
    return str(IPv4Address(subnet & mask))
