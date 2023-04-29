"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo(Topo):
    "Simple topology example."

    def build(self):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')

        # Add links
        self.addLink(s1, s2)
        self.addLink(s1, s6)
        self.addLink(s1, s3)
        self.addLink(s2, s7)
        self.addLink(s2, s4)
        self.addLink(s3, s6)
        self.addLink(s3, s4)
        self.addLink(s4, s7)
        self.addLink(h2, s6)
        self.addLink(h3, s1)
        self.addLink(h1, s3)
        self.addLink(h6, s4)
        self.addLink(h5, s7)
        self.addLink(h4, s2)


topos = {'mytopo': (lambda: MyTopo())}
