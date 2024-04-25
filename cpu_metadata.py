from scapy.fields import IntField, ShortField, ByteField, ByteEnumField, LongField, XIntField, PacketListField, IPField, LenField, ConditionalField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from utils import TYPE_OSPF, ALLSPFRouters, BIRTHDAY, TYPE_IPV4, TYPE_OSPF_HELLO, MASK_32, get_subnet_mask
import struct

TYPE_CPU_METADATA = 0x080a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 0),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", None)]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)

TYPE_HELLO = 1 
TYPE_LSU = 4 
class LinkStateAdvertisement(Packet):
    fields_desc = [
        IPField("subnet", "0.0.0.0"),  # Default route subnet
        IPField("mask", "255.255.255.0"),  # Common subnet mask
        IPField("router_id", "0.0.0.0")  # ID of neighboring router, 0 if none
    ]
class Pwospf(Packet): 
    name = "Pwospf" 
    fields_desc = [
            ByteField("version", 2), 
            ByteField("type", None),
            ShortField("packet_len", None), 
            IPField("router_id", None), 
            XIntField("area_id", None), 
            ShortField("checksum", None), 
            ShortField("autype", 0),
            LongField("authentication",0), 
            ConditionalField(
                IPField("mask", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("helloint", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("padding", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("seq", None), 
                lambda pkt: pkt.type == TYPE_LSU 
                ),
            ConditionalField(
                ShortField("ttl", None), 
                lambda pkt: pkt.type == TYPE_LSU 
                ),
            ConditionalField(
                XIntField("num_ads", None), 
                lambda pkt: pkt.type == TYPE_LSU
                ),
            ConditionalField(
                PacketListField("advertisements", [], LinkStateAdvertisement, count_from=lambda pkt: pkt.num_ads),
                lambda pkt: pkt.type == TYPE_LSU
                ),
            ]
    def post_build(self,p,pay): 
        if self.packet_len is None: 
            length = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", length) + p[4:] 
        return p + pay 

bind_layers(IP,Pwospf,proto=89) 
bind_layers(Pwospf,LinkStateAdvertisement,type=TYPE_LSU)
bind_layers(LinkStateAdvertisement,LinkStateAdvertisement) 
