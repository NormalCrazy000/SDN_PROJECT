# Si richiede l'uso del topology discovery
# ryu-manager --observe-links
# Domande al prof: TODO serve quel if

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp
import networkx as nx


class HopByHopSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def change_tree(self):
        # print("Cancella")
        # if len(self.tree_old) != 0:
        for datapath in self.oldDataPath.values():
            self.del_flow(datapath, 1)
        # print(ev)
        self.tree_old = {}
        self.nodesAndPort = {}
        self.switch_host = {}

    def create_list_hosts_switch(self):
        # lista con tutte le porte dello switch
        all_ports_connected = {}
        # lista con solo le porte dello switch collegate ad altri switch
        all_ports_connected_onlySwitch = {}
        # maschera per tenere traccia degli host di uno switch

        for switch in get_all_switch(self):
            # self.switch_host[switch.dp.id] = []
            all_ports_connected[switch.dp.id] = []

            for port in switch.ports:
                if (port.is_live() == True):
                    all_ports_connected[switch.dp.id].append(port.port_no)
                    # print("Cazzo2")
                # print(vars(port))
                # Aggiungi 0 per tenere tarccia degli host
            all_ports_connected_onlySwitch[switch.dp.id] = []

        # print(all_ports_connected.items())
        for link in get_all_link(self):
            # print(link.src.port_no)
            if (link.src.port_no not in all_ports_connected_onlySwitch[link.src.dpid]):
                all_ports_connected_onlySwitch[link.src.dpid].append(link.src.port_no)
            if (link.src.port_no not in all_ports_connected_onlySwitch[link.dst.dpid]):
                all_ports_connected_onlySwitch[link.dst.dpid].append(link.dst.port_no)
        # print(all_ports_connected_onlySwitch.items())
        for key in all_ports_connected.keys():
            # print("differenza")
            # print(set(all_ports_connected[key]))
            # print(set(all_ports_connected_onlySwitch[key]))
            self.switch_host[key] = list(set(all_ports_connected[key]) - set(all_ports_connected_onlySwitch[key]))
        # print(self.switch_host.items())

    def del_flow_initial(self, datapath):
        '''ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for switch in get_all_switch(self):
            for port in switch.ports:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(port.port_no)))
                datapath.send_msg(mod)
        '''

    def del_flow(self, datapath, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # print("canzella")
        # print(datapath.id)
        # Cosi si cancellano le regole ad un eventuale ricollegamento TODO CHEIDI prof
        for switch in get_all_switch(self):
            for port in switch.ports:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE_STRICT,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(port.port_no)), priority=1)
                datapath.send_msg(mod)
        '''try:
            for (port) in self.nodesAndPort[str(datapath.id)]:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(port)))
                datapath.send_msg(mod)
        except:
            print()

        for port in self.switch_host[datapath.id]:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY,
                                    match=parser.OFPMatch(in_port=int(port)))
            datapath.send_msg(mod)
         for host in get_all_host(self):
            if host.port.dpid == datapath.id:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(host.port.port_no)))
                datapath.send_msg(mod)
        '''

    def create_tree(self):
        net = nx.Graph()
        for link in get_all_link(self):
            # print(type(link))
            # print(link)
            if (net.has_edge(link.src.dpid, link.dst.dpid) == False):
                ports = {}
                ports[str(link.src.dpid)] = link.src.port_no;
                ports[str(link.dst.dpid)] = link.dst.port_no;
                net.add_edge(link.src.dpid, link.dst.dpid, info=ports)
                # print("Test: sorce: " + str(link.src.dpid) + ", " + str(link.src.port_no) + "----destination: " + str(link.dst.dpid) + ", " + str(link.dst.port_no) )
        T = nx.minimum_spanning_tree(net)
        return T

    @set_ev_cls(event.EventPortAdd)
    def _event_port_add_handler(self, ev):
        self.change_tree()
        # print("port add")
        # print(vars(ev.port))
        return

    @set_ev_cls(event.EventPortDelete)
    def _event_port_delete_handler(self, ev):
        self.change_tree()
        # print("port delete")
        return

    @set_ev_cls(event.EventPortModify)
    def _event_port_modify_handler(self, ev):
        self.change_tree()
        # print("port modify")
        # print(vars(ev))
        # print(vars(ev.port))
        return

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        self.change_tree()
        # print("link add")
        return

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        self.change_tree()
        # print("link delete")
        return

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        self.change_tree()
        # print("Switch enter")
        return

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        self.change_tree()
        # TODO
        self.oldDataPath.pop(ev.switch.dp.id)
        # print("Switch leave")
        # print(ev.switch)
        # print(ev.msg.datapath)
        return

    @set_ev_cls(event.EventSwitchReconnected)
    def _event_switch_reconnected_handler(self, ev):
        self.change_tree()
        # print("Switch reconnected")
        # print(ev.msg.datapath)
        return

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        self.change_tree()
        # print("host add")
        return

    @set_ev_cls(event.EventHostMove)
    def _event_host_add_handler(self, ev):
        self.change_tree()
        # print("host move")
        return

    @set_ev_cls(event.EventHostDelete)
    def _event_host_delete_handler(self, ev):
        self.change_tree()
        # print("host add")
        return

    def __init__(self, *args, **kwargs):
        super(HopByHopSwitch, self).__init__(*args, **kwargs)
        self.tree_old = {}
        self.oldDataPath = {}
        self.nodesAndPort = {}
        self.switch_host = {}
        self.i = 0

    # tutti i pacchetti al controllore
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # print("Switch: " + str(ev.msg.datapath.id) + "----CONFIG_DISPATCHER")
        datapath = ev.msg.datapath
        self.oldDataPath[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)
                ]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            instructions=inst
        )

        # remove old flow
        self.del_flow_initial(datapath)
        '''print("Test:")
        i=0
        for host in get_all_switch(self):
         for port in host.ports:
          print(port.port_no)
         print("----")
        '''

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # print("Switch: " + str(ev.msg.datapath.id) + "----MAIN_DISPATCHER")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        # se ARP esegui proxy arp
        '''if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.proxy_arp(msg)
            return
        '''
        # print("----")
        '''print("Check hosts:")
        for host in get_all_host(self):
          print(host.port.port_no)
        print("----")
        '''
        # TODO: serve questo if?
        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP and eth.ethertype != ether_types.ETH_TYPE_ARP:
            return
        if (len(self.tree_old) == 0):
            self.tree_old = self.create_tree()
            # print edges
            # print(self.tree_old.edges.data())
            self.nodesAndPort = {}
            self.switch_host = {}
            self.switch_host = {}

            self.create_list_hosts_switch()
            for (node, data) in self.tree_old.nodes(data=True):
                self.nodesAndPort[str(node)] = []
            # Cycle to add rules
            for (nodeSRC, nodeDST, data) in self.tree_old.edges(data=True):
                # print("DPPID src: " + str(nodeSRC))
                # print("\n")
                # print("DPPID dst: " + str(nodeDST))
                # print("\n")
                # print("Port src: " + str(data["portSRC"]))
                # print("\n")
                # print("Port dst: " + str(data["portDST"]))
                # print("\n")
                self.nodesAndPort[str(nodeSRC)].append(str(data["info"][str(nodeSRC)]))
                self.nodesAndPort[str(nodeDST)].append(str(data["info"][str(nodeDST)]))
            # print(self.nodesAndPort)
        # match = parser.OFPMatch(eth_dst=dst,eth_src=eth.src)
        match = parser.OFPMatch(in_port=in_port)

        actions = []
        # print("Test")
        # print("SWITCH: " + str(datapath.id))
        # print("Info:   ")
        # print(nodesAndPort)
        try:
            for (port) in self.nodesAndPort[str(datapath.id)]:
                if (int(port) != in_port):
                    # print("Ports: " + str(port))
                    actions.append(parser.OFPActionOutput(int(port)))
        except:
            print()
        for port in self.switch_host[datapath.id]:
            if port != in_port:
                actions.append(parser.OFPActionOutput(int(port)))
        '''for host in get_all_host(self):
            if host.port.dpid == datapath.id:
                if host.port.port_no != in_port:
                    actions.append(parser.OFPActionOutput(int(host.port.port_no)))
            '''
        # TODO: check this if
        '''if dst_dpid is None:
            print("Not ffffffffffffffff\n")
            # print "DP: ", datapath.id, "Host not found: ", pkt_ip.dst
            return
        '''
        # print(actions)
        if (len(actions) != 0):
            inst = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst
            )
            datapath.send_msg(mod)

            assert msg.buffer_id == ofproto.OFP_NO_BUFFER
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
        return
