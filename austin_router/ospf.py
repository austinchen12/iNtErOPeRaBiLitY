# from scapy.packet import Packet, bind_layers
# from scapy.fields import IntField, ShortField, ByteField, ByteEnumField, LongField, XIntField, PacketListField, IPField, LenField
# from scapy.layers.inet import IP
# from scapy.all import Ether
from datetime import datetime, timedelta
from utils import TYPE_OSPF, ALLSPFRouters, BIRTHDAY, TYPE_IPV4, TYPE_OSPF_HELLO, MASK_32, get_subnet_mask
from threading import Thread, Lock, Timer

class OSPFInterface():
    def __init__(self, sw, ip, mac, subnet, router_id, area_id, helloint):
        self.sw = sw
        self.ip = ip
        self.mac = mac
        self.subnet = subnet
        self.mask = get_subnet_mask(subnet)
        self.router_id = router_id
        self.area_id = area_id
        self.helloint = helloint
        self.thread = None
        self.neighbors = {}

    def update(self, neighbor_id, neighbor_ip, last_ping):
        self.neighbors[(neighbor_id, neighbor_ip)] = last_ping
    
    def get_ip(self, id):
        for neigh_id, neigh_ip in self.neighbors:
            if id == neigh_id:
                return neigh_ip
        return None
