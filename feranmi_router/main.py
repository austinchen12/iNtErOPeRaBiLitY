import sys
sys.path.append("/home/feranmi/p4app/docker/scripts")

from p4app import P4Mininet

from controller import Controller
from my_topo import SwitchTopo
from mininet.cli import CLI

# Topology consists of four hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SwitchTopo()
net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)

# Retrieve switch and host objects
h1, h2, h3 = net.get('h1'), net.get('h2'), net.get('h3')
h4, h5, h6 = net.get('h4'), net.get('h5'), net.get('h6')
h7, h8, h9 = net.get('h7'), net.get('h8'), net.get('h9')
h10, h11, h12 = net.get('h10'), net.get('h11'), net.get('h12')

s1, s2, s3, s4 = net.get("s1"), net.get("s2"), net.get("s3"), net.get("s4")

# Setup default gateways for the hosts to enable connectivity
h1.cmd("route add default gw 11.11.11.1")
h2.cmd("route add default gw 11.11.11.1")
h3.cmd("route add default gw 11.11.11.1")

h4.cmd("route add default gw 22.22.22.1")
h5.cmd("route add default gw 22.22.22.1")
h6.cmd("route add default gw 22.22.22.1")

h7.cmd("route add default gw 33.33.33.1")
h8.cmd("route add default gw 33.33.33.1")
h9.cmd("route add default gw 33.33.33.1")

h10.cmd("route add default gw 44.44.44.1")
h11.cmd("route add default gw 44.44.44.1")
h12.cmd("route add default gw 44.44.44.1")
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
switches = ["s1","s2","s3","s4"]

for switch in switches:
    sw = net.get(switch)
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 7))

    # Send MAC bcast packets to the bcast multicast group
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

cpu1_routerID = "0.0.0.1"
cpu2_routerID = "0.0.0.2"
cpu3_routerID = "0.0.0.3"
cpu4_routerID = "0.0.0.4"

cpu1_ips = ["11.11.11.1", "55.55.55.1"]
cpu2_ips = ["22.22.22.1", "55.55.55.2"]
cpu3_ips = ["33.33.33.1", "55.55.55.3"]
cpu4_ips = ["44.44.44.1", "55.55.55.4"]


cpu1_macs = ["00:00:00:00:00:10","00:00:00:00:00:11"]
cpu2_macs = ["00:00:00:00:00:20","00:00:00:00:00:21"]
cpu3_macs = ["00:00:00:00:00:30","00:00:00:00:00:31"]
cpu4_macs = ["00:00:00:00:00:40","00:00:00:00:00:41"]

cpu1_subnets = ["11.11.11.0/24", "55.55.55.0/24"]
cpu2_subnets = ["22.22.22.0/24", "55.55.55.0/24"]
cpu3_subnets = ["33.33.33.0/24", "55.55.55.0/24"]
cpu4_subnets = ["44.44.44.0/24", "55.55.55.0/24"]

cpu1_intfs_mappings = {cpu1_subnets[0]:(cpu1_macs[0],cpu1_ips[0]), cpu1_subnets[1]: (cpu1_macs[1], cpu1_ips[1])}
cpu2_intfs_mappings = {cpu2_subnets[0]:(cpu2_macs[0],cpu2_ips[0]), cpu2_subnets[1]: (cpu2_macs[1], cpu2_ips[1])}
cpu3_intfs_mappings = {cpu3_subnets[0]:(cpu3_macs[0],cpu3_ips[0]), cpu3_subnets[1]: (cpu3_macs[1], cpu3_ips[1])}
cpu4_intfs_mappings = {cpu4_subnets[0]:(cpu4_macs[0],cpu4_ips[0]), cpu4_subnets[1]: (cpu4_macs[1], cpu4_ips[1])}

# Start the MAC learning controller
cpu1 = Controller(s1, ["11.11.11.1", "55.55.55.1"], ["00:00:00:00:00:10","00:00:00:00:00:11"], ["11.11.11.0/24", "55.55.55.0/24"], cpu1_routerID)
cpu2 = Controller(s2, ["22.22.22.1", "55.55.55.2"], ["00:00:00:00:00:20","00:00:00:00:00:21"], ["22.22.22.0/24", "55.55.55.0/24"], cpu2_routerID)
cpu3 = Controller(s3, ["33.33.33.1", "55.55.55.3"], ["00:00:00:00:00:30","00:00:00:00:00:31"], ["33.33.33.0/24", "55.55.55.0/24"], cpu3_routerID)
cpu4 = Controller(s4, ["44.44.44.1", "55.55.55.4"], ["00:00:00:00:00:40","00:00:00:00:00:41"], ["44.44.44.0/24", "55.55.55.0/24"], cpu4_routerID)

# cpu1 = P4Controller(s1,cpu1_ips,cpu1_macs,cpu1_subnets,cpu1_intfs_mappings,cpu1_routerID,1)
# cpu2 = P4Controller(s2,cpu2_ips,cpu2_macs,cpu2_subnets,cpu2_intfs_mappings,cpu2_routerID,1)
# cpu3 = P4Controller(s3,cpu3_ips,cpu3_macs,cpu3_subnets,cpu3_intfs_mappings,cpu3_routerID,1)
# cpu4 = P4Controller(s4,cpu4_ips,cpu4_macs,cpu4_subnets,cpu4_intfs_mappings,cpu4_routerID,1)
mask = 0xFFFFFFFF

cpu1.routes.routes[("11.11.11.10", mask)] = "11.11.11.10"
cpu1.routes.routes[("11.11.11.20", mask)] = "11.11.11.20"
cpu1.routes.routes[("11.11.11.30", mask)] = "11.11.11.30"

cpu2.routes.routes[("22.22.22.10", mask)] = "22.22.22.10"
cpu2.routes.routes[("22.22.22.20", mask)] = "22.22.22.20"
cpu2.routes.routes[("22.22.22.30", mask)] = "22.22.22.30"

cpu3.routes.routes[("33.33.33.10", mask)] = "33.33.33.10"
cpu3.routes.routes[("33.33.33.20", mask)] = "33.33.33.20"
cpu3.routes.routes[("33.33.33.30", mask)] = "33.33.33.30"

cpu4.routes.routes[("44.44.44.10", mask)] = "44.44.44.10"
cpu4.routes.routes[("44.44.44.20", mask)] = "44.44.44.20"
cpu4.routes.routes[("44.44.44.30", mask)] = "44.44.44.30"


s1.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["11.11.11.10", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"11.11.11.10"},
    priority = 1,
)

s1.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["11.11.11.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"11.11.11.20"},
    priority = 1,
)

s1.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["11.11.11.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"11.11.11.30"},
    priority = 1,
)

s2.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["22.22.22.10", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"22.22.22.10"},
    priority = 1,
)

s2.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["22.22.22.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"22.22.22.20"},
    priority = 1,
)

s2.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["22.22.22.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"22.22.22.30"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["33.33.33.10", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"33.33.33.10"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["33.33.33.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"33.33.33.20"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["33.33.33.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"33.33.33.30"},
    priority = 1,
)

s4.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["44.44.44.10", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"44.44.44.10"},
    priority = 1,
)

s4.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["44.44.44.20", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"44.44.44.20"},
    priority = 1,
)

s4.insertTableEntry(
    table_name="MyIngress.routing_table",
    match_fields={"hdr.ipv4.dstAddr": ["44.44.44.30", mask]},
    action_name="MyIngress.set_next_hop",
    action_params={"next_hop":"44.44.44.30"},
    priority = 1,
)

cpu1.start()
cpu2.start()
cpu3.start()
cpu4.start()
CLI(net)
net.stop()