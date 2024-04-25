from ipaddress import IPv4Address, ip_network, ip_address
from datetime import datetime

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

TYPE_IPV4           = 0x800
TYPE_ARP            = 0x806
TYPE_CPU_METADATA   = 0x80a
TYPE_OSPF           = 89

HW_TYPE_ETHERNET    = 0x1

MASK_24 = "255.255.255.0"
MASK_32 = "255.255.255.255"

TYPE_OSPF_HELLO = 0x1
TYPE_OSPF_LSU = 0x4
ALLSPFRouters = "224.0.0.5"

BIRTHDAY = datetime(2002, 2, 28)

def create_subnet(ip, mask_ip):
    mask_hex = ip_to_hex(mask_ip)
    # to CIDR
    ip = int(IPv4Address(ip))
    network_int = ip & mask_hex
    mask_length = bin(mask_hex).count('1')
    return f"{IPv4Address(network_int)}/{mask_length}"

def add_mask_size(subnet, mask_ip):
    maskhex = ip_to_hex(mask_ip)
    # appends /size
    prefix_size = bin(maskhex).count('1')
    return '%s/%d' % (subnet, prefix_size)

def get_subnet_mask(subnet):
    # gets mask hex
    prefix = int(subnet.split('/')[1])
    return hex_to_ip((2 ** prefix - 1) << (32 - prefix))

def apply_mask(subnet, mask_ip):
    maskhex = ip_to_hex(mask_ip)
    if "/" in subnet:
        subnet = subnet.split("/")[0]
    subnet = int(IPv4Address(subnet))
    return str(IPv4Address(subnet & maskhex))

def ip_to_hex(ip_address):
    # Split the IP address into four octets
    octets = ip_address.split('.')
    
    # Calculate the decimal value of the IP address
    decimal_value = (int(octets[0]) << 24) + (int(octets[1]) << 16) + \
                    (int(octets[2]) << 8) + int(octets[3])
    
    return decimal_value

def hex_to_ip(decimal_value):
    octet1 = (decimal_value >> 24) & 0xFF
    octet2 = (decimal_value >> 16) & 0xFF
    octet3 = (decimal_value >> 8) & 0xFF
    octet4 = decimal_value & 0xFF
    
    ip_address = f"{octet1}.{octet2}.{octet3}.{octet4}"
    
    return ip_address