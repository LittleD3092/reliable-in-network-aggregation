#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI

class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1', ip = '10.0.1.1')
        h2 = self.addHost('h2', ip = '10.0.1.2')
        h3 = self.addHost('h3', ip = '10.0.2.1')

        # Add switches
        s1 = self.addSwitch('s1', cls = OVSSwitch, datapath = 'p4')
        s2 = self.addSwitch('s2', cls = OVSSwitch, datapath = 'p4')

        # Add links
        self.addLink(h1, s1, bw = 10)
        self.addLink(h2, s1, bw = 10)
        self.addLink(s1, s2, bw = 10)
        self.addLink(h3, s2, bw = 10)

def main():
    topo = MyTopo()
    net = Mininet(topo = topo, link = TCLink, controller = RemoteController)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()