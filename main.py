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

    #Questa funzione cancella l'albero
    def change_tree(self):
        for datapath in self.oldDataPath.values():
            self.del_flow(datapath, 1)
        self.tree_old = {}
        self.nodesAndPort = {}
        self.switch_host = {}

    #Questa funzione cerca le porte degli host
    def create_list_hosts_switch(self):
        # lista con tutte le porte dello switch
        all_ports_connected = {}
        # lista con solo le porte dello switch collegate ad altri switch
        all_ports_connected_onlySwitch = {}

        for switch in get_all_switch(self):
            all_ports_connected[switch.dp.id] = []

            for port in switch.ports:
                if (port.is_live() == True):
                    all_ports_connected[switch.dp.id].append(port.port_no)
            all_ports_connected_onlySwitch[switch.dp.id] = []

        for link in get_all_link(self):
            if (link.src.port_no not in all_ports_connected_onlySwitch[link.src.dpid]):
                all_ports_connected_onlySwitch[link.src.dpid].append(link.src.port_no)
            if (link.src.port_no not in all_ports_connected_onlySwitch[link.dst.dpid]):
                all_ports_connected_onlySwitch[link.dst.dpid].append(link.dst.port_no)
        for key in all_ports_connected.keys():
            self.switch_host[key] = list(set(all_ports_connected[key]) - set(all_ports_connected_onlySwitch[key]))

    #Questa funzione cancella regole non più in uso
    def del_flow(self, datapath, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for switch in get_all_switch(self):
            for port in switch.ports:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE_STRICT,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(port.port_no)), priority=1)
                datapath.send_msg(mod)


    #Questa funzione costruisce l'albero da un grafico non diretto
    def create_tree(self):
        net = nx.Graph()
        for link in get_all_link(self):
            if (net.has_edge(link.src.dpid, link.dst.dpid) == False):
                ports = {}
                ports[str(link.src.dpid)] = link.src.port_no;
                ports[str(link.dst.dpid)] = link.dst.port_no;
                net.add_edge(link.src.dpid, link.dst.dpid, info=ports)
        T = nx.minimum_spanning_tree(net)
        return T

    #Gestione di eventi vari per il cambio di topologia
    @set_ev_cls(event.EventPortAdd)
    def _event_port_add_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventPortDelete)
    def _event_port_delete_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventPortModify)
    def _event_port_modify_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        self.change_tree()
        self.oldDataPath.pop(ev.switch.dp.id)
        return

    @set_ev_cls(event.EventSwitchReconnected)
    def _event_switch_reconnected_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventHostMove)
    def _event_host_add_handler(self, ev):
        self.change_tree()
        return

    @set_ev_cls(event.EventHostDelete)
    def _event_host_delete_handler(self, ev):
        self.change_tree()
        return

    def __init__(self, *args, **kwargs):
        super(HopByHopSwitch, self).__init__(*args, **kwargs)
        #Albero
        self.tree_old = {}
        #Datapath degli switch per cancellare le regole
        self.oldDataPath = {}
        #Asscociazione tra switch e le sue porte che fanno parte dell'albero
        self.nodesAndPort = {}
        #Porte degli switch a cui sono connessi gli host
        self.switch_host = {}
        self.i = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
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


        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype != ether_types.ETH_TYPE_IP and eth.ethertype != ether_types.ETH_TYPE_ARP:
            return
        #Il codice seguente crea l'albero e le associazioni tra porte e switch
        if (len(self.tree_old) == 0):
            self.tree_old = self.create_tree()
            self.nodesAndPort = {}
            self.switch_host = {}
            self.switch_host = {}

            self.create_list_hosts_switch()
            for (node, data) in self.tree_old.nodes(data=True):
                self.nodesAndPort[str(node)] = []
            for (nodeSRC, nodeDST, data) in self.tree_old.edges(data=True):
                self.nodesAndPort[str(nodeSRC)].append(str(data["info"][str(nodeSRC)]))
                self.nodesAndPort[str(nodeDST)].append(str(data["info"][str(nodeDST)]))
        match = parser.OFPMatch(in_port=in_port)

        actions = []
        try:
            for (port) in self.nodesAndPort[str(datapath.id)]:
                if (int(port) != in_port):
                    actions.append(parser.OFPActionOutput(int(port)))
        except:
            print()
        for port in self.switch_host[datapath.id]:
            if port != in_port:
                actions.append(parser.OFPActionOutput(int(port)))
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
