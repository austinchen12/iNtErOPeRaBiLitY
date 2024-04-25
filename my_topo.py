from mininet.topo import Topo
from collections import defaultdict
from utils import apply_mask, MASK_32
from p4app import configureP4RuntimeSimpleSwitch


class TriangleSwitchTopo(Topo):
    
    def __init__(self, n, programs=None, **opts):
        self.tuples = defaultdict(list)
        Topo.__init__(self, **opts)

        
        switches = []
        s1 = self.addSwitch("s1")
        switches.append(s1)
        if programs:
            switch2 = configureP4RuntimeSimpleSwitch(programs[0], start_controller=True, enable_debugger=False)
            switch3 = configureP4RuntimeSimpleSwitch(programs[1], start_controller=True, enable_debugger=False)
            s2 = self.addSwitch("s2", cls=switch2)
            s3 = self.addSwitch("s3", cls=switch3)
            switches.append(s2)
            switches.append(s3)
        else:
            for i in range(2, 4): # 3 controllers
                s = self.addSwitch("s%d" % i)
                switches.append(s)

        for si, sw in enumerate(switches):
            for i in range(1, n + 1):
                hi = 3 * si + i
                ip = "10.0.%d.%d/24" % (si, i)
                mac = "00:00:00:00:%02x:%02x" % (si, i)
                h = self.addHost(
                    "h%d" % hi, ip=ip, mac=mac
                )
                self.addLink(h, sw, port2=i)

                self.tuples[sw].append((apply_mask(ip, MASK_32), mac, i))

        self.addLink(switches[0], switches[1], port1=4, port2=5)
        self.addLink(switches[1], switches[2], port1=4, port2=5)
        self.addLink(switches[2], switches[0], port1=4, port2=5)
