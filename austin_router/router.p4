/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<8> TYPE_OSPF          = 89;
const bit<8> TYPE_OSPF_HELLO    = 0x1;
const bit<8> TYPE_OSPF_LSU      = 0x4;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ospf_t {
    bit<8> version;
    bit<8> type;
    bit<16> packet_length;
    bit<32> router_id;
    bit<32> area_id; 
    bit<16> checksum;
    bit<16> autype;
    bit<64> authentication;
}

header ospf_hello_t {
    bit<32> network_mask;
    bit<16> helloint;
    bit<16> padding;
}

header ospf_lsu_t {
    bit<16>         sequence;
    bit<16>         ttl;
    bit<32>         lsa_count;
}

header ospf_lsa_list_t {
    varbit<960> ads;
}

struct ospf_lsa_t {
    bit<32>     subnet;
    bit<32>     mask;
    bit<32>     router_id;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    ospf_t            ospf;
    ospf_hello_t      ospf_hello;
    ospf_lsu_t        ospf_lsu;
    ospf_lsa_list_t   ospf_lsa_list;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_OSPF: parse_ospf_header;
            default: accept;
        }
    }

    state parse_ospf_header {
        packet.extract(hdr.ospf);
        transition select(hdr.ospf.type) {
            TYPE_OSPF_HELLO: parse_ospf_hello;
            TYPE_OSPF_LSU: parse_ospf_lsu;
            default: accept;
        }
    }

    state parse_ospf_hello {
        packet.extract(hdr.ospf_hello);
        transition accept;
    }

    state parse_ospf_lsu {
        packet.extract(hdr.ospf_lsu);
        transition select(hdr.ospf_lsu.lsa_count) {
            0: accept;
            default: parse_ospf_lsa;
        }
    }

    state parse_ospf_lsa {
        packet.extract(hdr.ospf_lsa_list, (bit<32>)(hdr.ospf_lsu.lsa_count * 32));
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    ip4Addr_t next_hop;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action set_l3_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_dst_ip(ip4Addr_t dst_ip) {
        next_hop = dst_ip;
    }

    action set_dst_mac(macAddr_t mac_addr) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac_addr;
    }

    table fwd_l3 {
        key = {
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            set_dst_ip;
            set_l3_mgid;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    table arp_table {
        key = {
            next_hop: ternary;
        }
        actions = {
            set_dst_mac;
            send_to_cpu;
            NoAction;
        }
        size = 1024;
        default_action = send_to_cpu;
    }

    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (!hdr.ospf_lsu.isValid() && !hdr.ospf_hello.isValid()) {
            if (hdr.arp.isValid()) {
                log_msg("@@ARP {}, {}, {}, {}, {}, {}", { hdr.arp.srcIP, hdr.arp.dstIP, hdr.ethernet.srcAddr, hdr.ethernet.dstAddr, hdr.arp.opcode, standard_metadata.ingress_port });
            }
            else if (hdr.ipv4.isValid()) {
                log_msg("@@IPV4 {}, {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
            }
        }

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        } else if (hdr.ospf_hello.isValid()) {
            if (standard_metadata.ingress_port == CPU_PORT) {
                fwd_l2.apply();  
            } else {
                send_to_cpu();
            }
        } else if (hdr.ospf_lsu.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        } else if (hdr.ipv4.isValid()) {
            if (fwd_l3.apply().hit) {
                if (arp_table.apply().hit) {
                    fwd_l2.apply();
                }
            }
        }
        else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ospf);
        packet.emit(hdr.ospf_hello);
        packet.emit(hdr.ospf_lsu);
        packet.emit(hdr.ospf_lsa_list);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;