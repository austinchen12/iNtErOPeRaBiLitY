import sys
sys.path.append("/home/austin/p4app/docker/scripts")

from p4app import P4Mininet
from mininet.cli import CLI

from oliver_router.controller import P4Controller as OliverController
from austin_router.controller import Controller as AustinController
from my_topo import TriangleSwitchTopo 

import sys
import time
import random



N = 3
interop_progs = ['interop/austin_router/router.p4', 'interop/austin_router/router.p4'] # TODO: change with your p4 script
topo = TriangleSwitchTopo(N, interop_progs)
net = P4Mininet(program='interop/austin_router/router.p4', topo=topo, auto_arp=False)
net.start()

bcast_mgid = 1
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

        if True: # sw.name == "s1"
            for i in range(2, N + 1):
                h = net.get("h%d" % (3 * si + i))
                h.cmd("route add default gw 10.0.%d.4" % si)

            r1_ips, r1_macs, r1_subnets = ["10.0.0.4", "10.0.3.0"], ["00:00:00:00:00:04", "00:00:00:00:03:00"], ["10.0.0.0/24", "10.0.3.0/24"]
            r1_config = {
                (2, 4): (r1_ips[0], r1_macs[0], r1_subnets[0], True),
                (4, 6): (r1_ips[1], r1_macs[1], r1_subnets[1], False)
            }
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
            
            controller = AustinController(sw, r1_ips, r1_macs, r1_config, 100, 1) # router_id 100, area_id 1
            controller.start()

        # else:
            # Start the controller
            # controller = OliverController(sw, cpu, topo) 
            # controller.start()

initialize_topology()

time.sleep(7)
CLI(net)
