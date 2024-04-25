from scapy.fields import IntField, ShortField, ByteField, ByteEnumField, LongField, XIntField, PacketListField, IPField, LenField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from utils import TYPE_OSPF, ALLSPFRouters, BIRTHDAY, TYPE_IPV4, TYPE_OSPF_HELLO, MASK_32, get_subnet_mask

TYPE_CPU_METADATA = 0x080a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 0),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", None)]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)

class OSPFHello(Packet):
    name = "OSPFHELLO"
    fields_desc = [
        IntField("network_mask", 0),
        ShortField("helloint", 0),
        ShortField("padding", 0)
    ]

class OSPFHeader(Packet):
    name = "OSPFHEADER"
    fields_desc = [
        ByteField("version", 2),
        ByteField("type", None),
        LenField("packet_length", None),
        IntField("router_id", None),
        IntField("area_id", None),
        ShortField("checksum", None),
        ShortField("autype", 0),
        LongField("authentication", 0)
    ]

class OSPFLSA(Packet):
    fields_desc = [
        IPField('subnet', None),
        IntField('mask', None),
        IntField('router_id', None),
    ]

class OSPFLSU(Packet):
    name = "OSPFLSU"
    fields_desc = [
        ShortField("sequence", None),
        ShortField("ttl", None),
        XIntField('lsa_count', None),
        PacketListField('lsa_list', [], OSPFLSA, count_from=lambda pkt: pkt.lsa_count)
    ]

bind_layers(IP, OSPFHeader, proto=TYPE_OSPF)
bind_layers(OSPFHeader, OSPFHello, type=1)
bind_layers(OSPFHeader, OSPFLSU, type=4)
bind_layers(OSPFLSU, OSPFLSA)
bind_layers(OSPFLSA, OSPFLSA)
