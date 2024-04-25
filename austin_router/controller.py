from threading import Thread, Event, Timer
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata, OSPFHeader, OSPFHello, OSPFLSA, OSPFLSU
import time
from ipaddress import ip_address, ip_network
from austin_router.ospf import OSPFInterface
from datetime import datetime, timedelta
from utils import ARP_OP_REQ, ARP_OP_REPLY
from utils import TYPE_IPV4, TYPE_ARP, TYPE_CPU_METADATA, TYPE_OSPF
from utils import TYPE_OSPF_HELLO, TYPE_OSPF_LSU
from utils import HW_TYPE_ETHERNET, MASK_24, MASK_32, ALLSPFRouters, BIRTHDAY, create_subnet, add_mask_size, get_subnet_mask, apply_mask
import heapq
from collections import defaultdict, deque
    
class Controller(Thread):
    def __init__(self, sw, ips, macs, config, router_id, area_id, start_wait=0.3):
        super(Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.mac_to_port = {}
        self.ip_to_mac = { ip: mac for ip, mac in zip(ips, macs) }
        self.routing_table = {}
        self.ips = ips
        self.macs = macs
        self.subnet_mapping = { subnet: (ip, mac, is_static) for ip, mac, subnet, is_static in config.values() } # subnet --> (mac, IP). Keep track of subnets because each port in the same subnet has the same IP/Mac
        self.pktcache = {}
        self.stop_event = Event()

        # OSPF stuff
        self.ip = self.ips[-1] # sorted so largest is at the end
        self.mac = self.macs[-1] # corresponding mac is also at the end
        self.router_id = router_id
        self.area_id = area_id
        self.lsuint = 3
        self.helloint = 1
        
        self.ospf_thread = Thread(target=self.ospfLSALoop)
        self.sequence = 0
        
        self.ospf_interfaces = { port: OSPFInterface(self.sw, t[0], t[1], t[2], self.router_id, self.area_id, self.helloint) for port, t in config.items() if not t[3] } # TODO: for ports, t in config.items() for port in range(*ports)
        # self.lsdb = { self.router_id: set((subnet.split('/')[0], get_subnet_mask(subnet), self.router_id) for subnet in self.subnet_mapping) }
        self.lsdb = { self.router_id: set((ip, get_subnet_mask(subnet)) for ip, mac, subnet, is_static in config.values()) }
        self.adj = defaultdict(set)

    def send_hello(self):
        for intf in self.ospf_interfaces.values():
            pkt = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
                            / CPUMetadata(origEtherType=TYPE_IPV4)
                            / IP(src=intf.ip, dst=ALLSPFRouters, proto=TYPE_OSPF)
                            / OSPFHeader(type=TYPE_OSPF_HELLO, router_id=self.router_id, area_id=self.area_id)
                            / OSPFHello(network_mask=intf.mask, helloint=self.helloint)
                    )
            self.send(pkt)
            print('@@HELLO', self.sw.name, intf.ip)

        # to_be_deleted = []
        # for key, last_ping in self.neighbors.items():
        #     if datetime.now() >= last_ping + timedelta(seconds=self.helloint * 3):
        #         # neighbor isn't saying hello back. ok deleted. cya nerd
        #         to_be_deleted.append(key)
        # for key in to_be_deleted:
        #     self.sw.removeTableEntry(
        #         table_name="MyIngress.fwd_l3",
        #         match_fields={"hdr.ipv4.dstAddr": [key[1], MASK_32]},
        #         action_name="MyIngress.set_dst_ip",
        #         action_params={"dst_ip":key[1]},
        #         priority = 1,
        #     )
        #     del self.neighbors[key]

        Timer(self.helloint, self.send_hello).start()

    def ospfLSALoop(self):
        return
        prev_time = BIRTHDAY
        count = 0
        while count < 2:
            time.sleep(self.lsuint)
            # if datetime.now() >= prev_time + timedelta(seconds=self.lsuint):
            # print('@@LOOP', self.sw.name, self.lsdb)
            self._floodLSU()
            # prev_time = datetime.now()
            count += 1
            # print('@@END', self.sw.name, self.adj, self.lsdb, self.ip_to_mac, self.mac_to_port, self.routing_table, [(*k, intf.neighbors) for k, intf in self.ospf_interfaces.items()])
            
            # to_be_deleted = []
            # for router_id, lsa in self.lsdb.items(): # TODO: changed here??
            #     if datetime.now() >= lsa['last_ping'] + timedelta(seconds=self.lsuint * 3):
            #         to_be_deleted.append(router_id)
            # for router_id in to_be_deleted:
            #     # delete outdated entry
            #     del self.lsdb[router_id]
            # if len(to_be_deleted) > 0:
            #     self._floodLSU()
    
    def _floodLSU(self):
        lsa_tuples = set()
        for router_id in self.lsdb:
            for ip, mask in self.lsdb[router_id]:
                lsa_tuples.add((apply_mask(ip, mask), mask, router_id))
        
        lsa_list = []
        for subnet, mask, router_id in lsa_tuples:
            lsa_list.append(OSPFLSA(subnet=subnet, mask=mask, router_id=router_id))
        lsa_list.reverse()
        self.sequence += 1
        # print('@@FLOOD', self.sw.name, self.adj[self.router_id])

        for router_id in self.adj[self.router_id]:
            src_ip, dst_ip = None, None
            for intf in self.ospf_interfaces.values():
                dst_ip = intf.get_ip(router_id)
                if dst_ip: break

            for subnet, entry in self.subnet_mapping.items():
                if ip_address(dst_ip) in ip_network(subnet):
                    src_ip = entry[0]
                    break
            # print('@@FLD_SEND', self.sw.name, src_ip, dst_ip)
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff")
                    / CPUMetadata(origEtherType=TYPE_IPV4)
                    / IP(src=src_ip, dst=dst_ip, proto=TYPE_OSPF)
                    / OSPFHeader(type=TYPE_OSPF_LSU, router_id=self.router_id, area_id=self.area_id) 
                    / OSPFLSU(sequence=self.sequence, lsa_count=len(lsa_list), lsa_list=lsa_list)
            )
            if dst_ip in self.ip_to_mac:
                self.send(pkt)
            elif dst_ip:
                # make ARP request
                print('@@wtf2', self.sw.name, dst_ip, router_id, self.adj[self.router_id])
                self.sendArpRequest(pkt, dst_ip)
            # else:
                # print('@@wtf1', self.sw.name, router_id)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.mac_to_port: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.mac_to_port[mac] = port

    def addIPAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.ip_to_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop': [ip, MASK_32]},
                action_name='MyIngress.set_dst_mac',
                action_params={'mac_addr': mac},
                priority = 1)
        self.ip_to_mac[ip] = mac

    def handleArpReply(self, pkt):
        # TODO: need protection
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)

        if pkt[ARP].psrc in self.ips:
            return

        dst_ip = pkt[ARP].pdst
        if dst_ip in self.ips and dst_ip in self.pktcache:
            # An ARP request we sent, meaning we want to continue with the original packet
            cached_pkt = self.pktcache[dst_ip]
            cached_pkt[Ether].dst = pkt[Ether].dst
            pkt = cached_pkt

            del self.pktcache[dst_ip]
            self.handleIPRequest(pkt)
        else:
            self.send(pkt)

    def handleArpRequest(self, pkt):
        if pkt[ARP].psrc in self.ips:
            # ArpRequest we sent out
            return

        # TODO: need protection
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)

        dst_ip = pkt[ARP].pdst
        if dst_ip in self.ips:
            # dst_ip belongs to this controller, so we want to reply
            self.sendArpReply(pkt)
        else:
            # only forward ARP packet if the target is in one of the subnets
            for s in self.subnet_mapping:
                if ip_address(pkt[ARP].pdst) in ip_network(s):
                    self.send(pkt)
                    break
    
    def sendArpReply(self, pkt):
        subnet = None
        dst_ip = pkt[ARP].pdst
        for s in self.subnet_mapping:
            if ip_address(dst_ip) in ip_network(s):
                subnet = s

        # Alter pkt to reply
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        pkt[ARP].hwsrc = self.subnet_mapping[subnet][1]
        pkt[ARP].pdst = pkt[ARP].psrc
        pkt[ARP].psrc = self.subnet_mapping[subnet][0]

        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = pkt[ARP].hwsrc

        self.send(pkt)

    def handleIPRequest(self, pkt):
        if pkt[IP].dst in self.ip_to_mac:
            self.send(pkt)
            return

        next_hop = None
        for key, value in self.routing_table.items():
            if ip_address(pkt[IP].dst) in ip_network(key):
                next_hop = value
                break

        if next_hop in self.ip_to_mac:
            self.send(pkt)
        else:
            # make ARP request
            print('@@wtf3', self.sw.name, pkt[IP].src, pkt[IP].dst, next_hop, self.ip_to_mac)
            self.sendArpRequest(pkt, next_hop)

    def sendArpRequest(self, pkt, target_ip):
        # cpu_metadata = pkt[CPUMetadata]
        # cpu_metadata.origEthertype = TYPE_ARP
        src_ip = src_mac = None # TODO: refactor this to handleIPRequest
        for s in self.subnet_mapping: # what happens if this fails
            # print('@@WTF', self.sw.name, target_ip, s)
            if ip_address(target_ip) in ip_network(s):
                src_ip, src_mac = self.subnet_mapping[s][0], self.subnet_mapping[s][1]

        self.pktcache[src_ip] = pkt

        eth_header = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        cpu_header = CPUMetadata(srcPort=pkt[CPUMetadata].srcPort)
        arp_header = ARP(op=1, pdst=target_ip, hwlen=6, plen=4, psrc=src_ip, hwsrc=src_mac, hwtype=HW_TYPE_ETHERNET, ptype=TYPE_IPV4)
        req = eth_header / cpu_header / arp_header
        self.send(req)

    def handleOSPFHello(self, pkt):
        src_ip = pkt[IP].src
        if pkt[OSPFHeader].area_id != self.area_id:
            return

        print('@@handle_hello', self.sw.name, src_ip)
        for intf in self.ospf_interfaces.values():
            if ip_address(src_ip) in ip_network(intf.subnet):
                # TODO: intf == self.ospf_interfaces[pkt[CPUMetadata].srcPort]
                mask = pkt[OSPFHello].network_mask
                helloint = pkt[OSPFHello].helloint
                if mask != intf.mask or helloint != intf.helloint:
                    return

                # print('@handle_HELLO', self.sw.name, src_ip, pkt[Ether].src, pkt[CPUMetadata].srcPort)
                self.addMacAddr(pkt[Ether].src, pkt[CPUMetadata].srcPort)
                self.addIPAddr(pkt[IP].src, pkt[Ether].src)


                router_id = pkt[OSPFHeader].router_id
                if (router_id, src_ip) not in intf.neighbors:
                    self.lsdb[router_id] = set([(src_ip, intf.mask)])
                    
                    self.adj[self.router_id].add(router_id)
                    self.adj[router_id].add(self.router_id)

                    subnet = create_subnet(src_ip, MASK_32)
                    if subnet not in self.routing_table:
                        self.routing_table[subnet] = src_ip
                        # print('@@INSERT B', self.sw.name, (apply_mask(subnet, MASK_32), MASK_32, src_ip))
                        self.sw.insertTableEntry(
                            table_name="MyIngress.fwd_l3",
                            match_fields={"hdr.ipv4.dstAddr": [apply_mask(subnet, MASK_32), MASK_32]},
                            action_name="MyIngress.set_dst_ip",
                            action_params={"dst_ip": src_ip},
                            priority = 2,
                        )
                    intf.update(router_id, src_ip, datetime.now())
                    # self._floodLSU() # flood since topo changed
                else:
                    intf.update(router_id, src_ip, datetime.now())
                return
        assert False # should never receive a hello packet from a non-neighbor

    def handleOSPFLSU(self, pkt):
        router_id = pkt[OSPFHeader].router_id
        if router_id == self.router_id:
            return
        
        lsa_list = []
        lsa = pkt[OSPFLSU].lsa_list[0]
        for intf in self.ospf_interfaces.values():
            if ip_address(pkt[IP].src) in ip_network(intf.subnet):
                break
        else:
            # unknown subnet
            print('@@UNKNOWN SUBNET', self.sw.name, pkt[IP].src)
            return

        # print('@@HANDLE_LSU', self.sw.name, pkt[IP].src, self.lsdb)
        for i in range(pkt[OSPFLSU].lsa_count):
            rid = lsa.router_id
            lsa_list.append(lsa)
            lsa = lsa.payload

        for lsa in lsa_list:
            rid = lsa.router_id
            if rid == self.router_id:
                # don't care about our own LSAs
                continue

            if rid not in self.lsdb:
                print('@@ROUTER_ID MISMATCH A', self.sw.name, rid, self.lsdb, self.adj, [intf.neighbors for intf in self.ospf_interfaces.values()])
                # self.adj[router_id].add(rid)
                # self.adj[rid].add(router_id)
                self.lsdb[rid] = set()
            
            subnet, mask = lsa.subnet, lsa.mask
            flood_update = False
            if (subnet, mask) not in self.lsdb[rid]:
                self.lsdb[rid].add((subnet, mask))
                flood_update = True
            
            adj = defaultdict(set)
            for intf in self.ospf_interfaces.values(): # TODO: 
                router_id = intf.router_id
                for neigh_id, neigh_ip in intf.neighbors:
                    adj[router_id].add(neigh_id)
                    adj[neigh_id].add(router_id)
            assert "\n".join(f"{k}: " + " ".join(map(str, sorted(v))) for k, v in self.adj.items() if len(v)) == "\n".join(f"{k}: " + " ".join(map(str, sorted(v))) for k, v in adj.items() if len(v))
            
            next_hops = self.get_next_hops(self.router_id)

            next_id = next_hops[rid]
            next_ip = None
            for intf in self.ospf_interfaces.values():
                next_ip = intf.get_ip(next_id)
                if next_ip: break

            if next_ip:
                # route of non-immediate neighbor (like host route or one over router)
                # drop for now?
                net = create_subnet(subnet, mask)
                if net in self.routing_table:
                    # print('@@DELETE A', self.sw.name, (subnet, mask, rid), (apply_mask(net, mask), mask, self.routing_table[net]), self.routing_table)
                    self.sw.removeTableEntry(
                        table_name="MyIngress.fwd_l3",
                        match_fields={"hdr.ipv4.dstAddr": [apply_mask(net, mask), mask]},
                        action_params={"dst_ip": self.routing_table[net]},
                        priority = 1 if mask == MASK_24 else 2,
                    )
                self.routing_table[net] = next_ip
                # print('@@INSERT A', self.sw.name, (subnet, mask, rid), (apply_mask(net, mask), mask, next_ip), self.routing_table)
                self.sw.insertTableEntry(
                    table_name="MyIngress.fwd_l3",
                    match_fields={"hdr.ipv4.dstAddr": [apply_mask(net, mask), mask]},
                    action_name="MyIngress.set_dst_ip",
                    action_params={"dst_ip": next_ip},
                    priority = 1 if mask == MASK_24 else 2,
                )
                # if flood_update: self._floodLSU()
            else:
                print('@@preadj', self.sw.name, rid, next_hops, self.adj, adj)
                print('@@waitwtf', self.sw.name, next_id, next_ip, (lsa.subnet, lsa.mask, lsa.router_id), [intf.neighbors for intf in self.ospf_interfaces.values()])
        # print('@@LSU_HANDLE_END', self.sw.name, self.routing_table)
        # self.send(pkt)
        
    
    def get_next_hops(self, src):
        next_hop = defaultdict(lambda: None)
        def bfs(dst):
            parents = {n: -1 for n in self.adj}
            dist = {n: float('inf') for n in self.adj}
            q = deque([src])
            dist[src] = 0

            while q:
                node = q.popleft()
                for neighbor in self.adj[node]:
                    if dist[neighbor] == float('inf'):
                        parents[neighbor] = node
                        dist[neighbor] = dist[node] + 1
                        q.append(neighbor)
            
            path, curr = [dst], dst
            while parents[curr] != -1:
                path.append(parents[curr])
                curr = parents[curr]
            return path[-2] if len(path) > 1 else None
        
        for node in self.adj:
            if node == src: continue
            next_hop[node] = bfs(node)
        return next_hop
    
    # def recomputeRoutingTable(self):
    #     adj = defaultdict(list)
    #     networks = {}
    #     for intf in self.ospf_interfaces.values(): # TODO: 
    #         router_id = intf.router_id
    #         for neigh_id, neigh_ip in intf.neighbors:
    #             if router_id not in adj: adj[router_id] = set()
    #             if neigh_id not in adj: adj[neigh_id] = set()
    #             adj[router_id].add(neigh_id)
    #             adj[neigh_id].add(router_id)
    #             netaddr = add_mask_size(neigh_ip, intf.mask) # TODO: is intf.mask correct?
    #             if netaddr not in networks:
    #                 networks[netaddr] = set()
    #             networks[netaddr].add(router_id)

    #     next_hops = self.get_next_hops(adj, self.router_id)
    #     ospf_table = dict()

    #     for netaddr, nodes in networks.items():
    #         next_r_id = None
    #         for r_id in nodes:
    #             if r_id != self.router_id and r_id in next_hops:
    #                 next_r_id = next_hops[r_id]
    #                 break
            
    #         for port, intf in self.ospf_interfaces.items():
    #             next_ip = None
    #             for n_id, n_ip in intf.neighbors:
    #                 if n_id == next_r_id:
    #                     next_ip = n_ip
    #             if create_subnet(intf.ip, intf.mask) == netaddr:
    #                 next_ip = '0.0.0.0'
    #             if next_ip is not None:
    #                 ospf_table[netaddr] = (next_ip, port)
        
    #     for netaddr, r in ospf_table.items():
    #         ip, prefixlen = netaddr.split('/')
    #         subnet_with_mask = str
    #         if r != self.routing_table.get(netaddr):
    #             if netaddr in self.routing_table:
    #                 self.sw.removeTableEntry(table_name='MyIngress.fwd_l3',
    #                                     match_fields={'hdr.ipv4.dstAddr': [ip, get_subnet_mask(netaddr)]})
    #             self.sw.insertTableEntry(table_name='MyIngress.fwd_l3',
    #                                 match_fields={'hdr.ipv4.dstAddr': [ip, get_subnet_mask(netaddr)]},
    #                                 action_name='MyIngress.set_dst_ip',
    #                                 action_params={'dst_ip': r[0]},
    #                                 priority=1)
    #             self.routing_table[netaddr] = r
        
    #     # to_be_deleted = [netaddr for netaddr in self.routing_table
    #     #                   if netaddr not in ospf_table]
    #     # for netaddr in to_be_deleted:
    #     #     del self.routing_table[netaddr]

    def handlePkt(self, pkt):
        # Ignore packets that the CPU sends:
        if CPUMetadata not in pkt or pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

        if OSPFHeader in pkt:
            if pkt[OSPFHeader].type == TYPE_OSPF_HELLO:
                self.handleOSPFHello(pkt)
            elif pkt[OSPFHeader].type == TYPE_OSPF_LSU:
                self.handleOSPFLSU(pkt)
            else:
                assert False
        elif IP in pkt:
            self.handleIPRequest(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        self.send_hello()
        self.ospf_thread.start()
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(Controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)