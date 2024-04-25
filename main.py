import sys
sys.path.append("/home/parallels/p4app/docker/scripts")

from p4app import P4Mininet
from mininet.cli import CLI

from oliver_router.controller import P4Controller as OliverController
from austin_router.controller import Controller as AustinController
from my_topo import TriangleSwitchTopo 

import sys
import time
import random


N = 3
interop_progs = ['oliver_router/l2switch.p4', 'austin_router/router.p4'] # TODO: change with your p4 script
topo = TriangleSwitchTopo(N, interop_progs)
net = P4Mininet(program='oliver_router/l2switch.p4', topo=topo, auto_arp=False)
net.start()

bcast_mgid = 1

def configure_oli(sw,host_ips,no): 
    #IPs, Macs, Subnets, Tuples 
    cpu1_ips = ["10.0.0.4","10.0.3.0"]
    cpu2_ips = ["10.0.1.4", "10.0.3.1"]
    cpu3_ips = ["10.0.2.4", "10.0.3.2"]
    cpu1_macs = ["00:00:00:00:00:10","00:00:00:00:00:11"]
    cpu2_macs = ["00:00:00:00:00:20","00:00:00:00:00:21"]
    cpu3_macs = ["00:00:00:00:00:30","00:00:00:00:00:31"]
    cpu1_subnets = ["10.0.0.0/24", "10.0.3.0/24"] 
    cpu2_subnets = ["10.0.1.0/24", "10.0.3.0/24"] 
    cpu3_subnets = ["10.0.2.0/24", "10.0.3.0/24"] 
    cpu1_intfs_mappings = {cpu1_subnets[0]:(cpu1_macs[0],cpu1_ips[0]), cpu1_subnets[1]: (cpu1_macs[1], cpu1_ips[1])}
    cpu2_intfs_mappings = {cpu2_subnets[0]:(cpu2_macs[0],cpu2_ips[0]), cpu2_subnets[1]: (cpu2_macs[1], cpu2_ips[1])}
    cpu3_intfs_mappings = {cpu3_subnets[0]:(cpu3_macs[0],cpu3_ips[0]), cpu3_subnets[1]: (cpu3_macs[1], cpu3_ips[1])}
    #Helper functions
    def add_cpu_host(cpu,ip,sw):
        cpu.routes.routes[(ip,0xFFFFFFFF)] = ip
        sw.insertTableEntry(
            table_name="MyIngress.fwd_l3",
            match_fields={"hdr.ipv4.dstAddr": [ip,0xFFFFFFFF]},
            action_name="MyIngress.set_dst_ip",
            action_params={"next_hop":ip},
            priority = 1,
        )
    cpu1_rid = "0.0.0.1"
    cpu2_rid = "0.0.0.2"
    cpu3_rid = "0.0.0.3"

    ret_cpu = None 
    if no == 1: 
        ret_cpu = OliverController(sw,cpu1_ips,cpu1_macs,cpu1_subnets,cpu1_intfs_mappings,cpu1_rid,1)
    elif no == 2: 
        ret_cpu = OliverController(sw,cpu2_ips,cpu2_macs,cpu2_subnets,cpu2_intfs_mappings,cpu2_rid,1)
    elif no == 3:
        ret_cpu = OliverController(sw,cpu3_ips,cpu3_macs,cpu3_subnets,cpu3_intfs_mappings,cpu3_rid,1) 
    for h_ip in host_ips: 
        add_cpu_host(ret_cpu,h_ip,ret_cpu.sw) 
    print(f"{ret_cpu.sw}: {ret_cpu.routes.routes} {ret_cpu.intfs_mappings}") 
    return ret_cpu 

def initialize_topology():
    for si in range(3):
        sw = net.get("s%d" % (si + 1))
        sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 6))

        # Send MAC bcast packets to the bcast multicast group
        sw.insertTableEntry(
            table_name="MyIngress.fwd_l2",
            match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
            action_name="MyIngress.set_mgid",
            action_params={"mgid": bcast_mgid},
        )

        for i in range(2, N + 1):
            h = net.get("h%d" % (3 * si + i))
            h.cmd("route add default gw 10.0.%d.4" % si)
        host_ips = [["10.0.0.1","10.0.0.2", "10.0.0.3"], ["10.0.1.1", "10.0.1.2", "10.0.1.3"], ["10.0.2.1", "10.0.2.2", "10.0.2.3"]] 
        if si == 0: 
            cpu = configure_oli(sw,host_ips[si],si+1) 
        elif si == 1: 
            cpu = configure_oli(sw,host_ips[si],si+1) 
        else:
            for ip, mac, port in topo.tuples[sw.name]:
                sw.insertTableEntry(
                    table_name="MyIngress.fwd_l3",
                    match_fields={"hdr.ipv4.dstAddr": [ip, 0xFFFFFFFF]},
                    action_name="MyIngress.set_dst_ip",
                    action_params={"dst_ip": ip},
                    priority = 2,
                )
                sw.insertTableEntry(
                    table_name="MyIngress.arp_table",
                    match_fields={"next_hop": [ip, 0xFFFFFFFF]},
                    action_name="MyIngress.set_dst_mac",
                    action_params={"mac_addr": mac},
                    priority = 1,
                )
                sw.insertTableEntry(
                    table_name="MyIngress.fwd_l2",
                    match_fields={"hdr.ethernet.dstAddr": mac},
                    action_name="MyIngress.set_egr",
                    action_params={"port": port},
                )

            r1_ips, r1_macs, r1_subnets = [f"10.0.{si}.4", f"10.0.3.{si}"], [f"00:00:00:00:0{si}:04", f"00:00:00:00:03:0{si}"], [f"10.0.{si}.0/24", "10.0.3.0/24"]
            r1_config = {
                (2, 4): (r1_ips[0], r1_macs[0], r1_subnets[0], True),
                (4, 6): (r1_ips[1], r1_macs[1], r1_subnets[1], False)
            }
                        
            cpu = AustinController(sw, r1_ips, r1_macs, r1_config, si, 1) # router_id si, area_id 1

        cpu.start()


initialize_topology()

time.sleep(5)
CLI(net)
