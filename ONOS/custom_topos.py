#!/usr/bin/python

from mininet.topo import Topo

class ComplexHierarchicalTopo(Topo):
    def build(self):
        # Core switches
        core1 = self.addSwitch('s1')
        core2 = self.addSwitch('s2')
        core3 = self.addSwitch('s3')

        # Aggregation switches
        agg1 = self.addSwitch('s4')
        agg2 = self.addSwitch('s5')
        agg3 = self.addSwitch('s6')
        agg4 = self.addSwitch('s7')

        # Edge switches list (s8 to s25)
        edge_switches = []
        for i in range(18):  # 25 - 7 = 18 edge switches
            switch = self.addSwitch('s{}'.format(8 + i))
            edge_switches.append(switch)

        # Hosts list (2 per edge switch = 36 hosts)
        hosts = []
        for i in range(36):
            host = self.addHost('h{}'.format(1 + i))
            hosts.append(host)

        # Core to Aggregation connections
        self.addLink(core1, agg1)
        self.addLink(core1, agg2)
        self.addLink(core2, agg2)
        self.addLink(core2, agg3)
        self.addLink(core3, agg3)
        self.addLink(core3, agg4)
        self.addLink(core1, agg4)  # Extra redundancy

        # Aggregation to Edge connections (distribute evenly)
        for i in range(18):
            if i < 5:
                self.addLink(agg1, edge_switches[i])
            elif i < 10:
                self.addLink(agg2, edge_switches[i])
            elif i < 14:
                self.addLink(agg3, edge_switches[i])
            else:
                self.addLink(agg4, edge_switches[i])

        # Edge to Hosts connections (2 hosts per edge switch)
        for i in range(18):
            self.addLink(edge_switches[i], hosts[2 * i])
            self.addLink(edge_switches[i], hosts[2 * i + 1])

topos = {'hiertopo': (lambda: ComplexHierarchicalTopo())}

