import sys
sys.path.append("/home/austin/p4app/docker/scripts")

from p4app import P4Mininet
from mininet.cli import CLI

from evan_router.controller import EvanController
from austin_router.controller import AustinController
from my_topo import SingleSwitchTopo, TwoSwitchTopo, ThreeSwitchTopo, RingTopology 

import sys
import time
import random



N = 2
interop_progs = ['interop/oliver_router/l2switch.p4', 'interop/austin_router/router.p4']
topo = ThreeSwitchTopo(N, interop_progs)
net = P4Mininet(program='interop/oliver_router/l2switch.p4', topo=topo, auto_arp=False)
net.start()

switches = topo.get_switches(net)
hosts = topo.get_hosts(net)
cpus = topo.get_control_planes(net)

# print('Interfaces:')
def initialize_topology():
    for switch, cpu in zip(switches, cpus):
        bcast_mgid = 1
        switch.addMulticastGroup(mgid=bcast_mgid, ports=range(bcast_mgid+1, N+1+1+2))

        # Send MAC bcast packets to the bcast multicast group
        switch.insertTableEntry(
            table_name="MyIngress.fwd_l2",
            match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
            action_name="MyIngress.set_mgid",
            action_params={"mgid": bcast_mgid},
        )

        if switch.name == "s3":
            r1_ips, r1_macs, r1_subnets = ["10.0.3.6", "10.0.4.3"], ["00:00:00:00:03:06", "00:00:00:00:04:03"], ["10.0.3.0/24", "10.0.4.0/24"]
            r1_config = {
                (2, 4): (r1_ips[0], r1_macs[0], r1_subnets[0], True),
                (4, 6): (r1_ips[1], r1_macs[1], r1_subnets[1], False)
            }
            for ip, mac, port in topo.tuples:
                switch.insertTableEntry(
                    table_name="MyIngress.fwd_l3",
                    match_fields={"hdr.ipv4.dstAddr": [ip, 0xFFFFFFFF]},
                    action_name="MyIngress.set_dst_ip",
                    action_params={"dst_ip": ip},
                    priority = 2,
                )
                switch.insertTableEntry(
                    table_name="MyIngress.arp_table",
                    match_fields={"next_hop": [ip, 0xFFFFFFFF]},
                    action_name="MyIngress.set_dst_mac",
                    action_params={"mac_addr": mac},
                    priority = 1,
                )
                switch.insertTableEntry(
                    table_name="MyIngress.fwd_l2",
                    match_fields={"hdr.ethernet.dstAddr": mac},
                    action_name="MyIngress.set_egr",
                    action_params={"port": port},
                )
            
            controller = AustinController(switch, r1_ips, r1_macs, r1_config, 100, 1) # router_id 100, area_id 1
            controller.start()

            for i in range(1, N+1):
                h = net.get(f'h{i}_{3}')
                h.cmd("route add default gw 10.0.3.0")

        else:
            # Add a mcast group for all ports (except for the CPU port)
            for ip in topo.get_port_to_intf_ip(switch, print_topo=False).values():
                switch.insertTableEntry(table_name='MyIngress.local_forwarding',
                        match_fields={'hdr.ipv4.dstAddr': [ip]},
                        action_name='MyIngress.send_to_cpu')

            # Start the controller
            controller = EvanController(switch, cpu, topo) 
            controller.start()

initialize_topology()

time.sleep(7)
CLI(net)
