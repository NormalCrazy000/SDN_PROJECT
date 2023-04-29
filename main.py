# Si richiede l'uso del topology discovery
# ryu-manager --observe-links
# Da gestire: 1) cambio di topologia
#

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
        if(len(self.tree_old)!=0):
            for datapath in self.oldDataPath.values():
                self.del_flow(datapath, 1)
            #print(ev)
            self.tree_old = {}
            self.nodesAndPort = {}

    def del_flow(self, datapath, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            for (port) in self.nodesAndPort[str(datapath.id)]:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(port)))
                datapath.send_msg(mod)
        except:
            print()
        for host in get_all_host(self):
            if host.port.dpid == datapath.id:
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=parser.OFPMatch(in_port=int(host.port.port_no)))
                datapath.send_msg(mod)


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

    def remove_flow(self):
        for switches in get_all_switch():
            switches.da

    # TODO:
    '''
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        print(ev.msg.datapath.id)
        print(body)
         for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
                             
        return
    '''

    @set_ev_cls(event.EventPortAdd)
    def _event_port_add_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()
        print("port add")

        return

    @set_ev_cls(event.EventPortDelete)
    def _event_port_delete_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("port delete")

        return

    @set_ev_cls(event.EventPortModify)
    def _event_port_modify_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("port modify")

        return

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("link add")

        return

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        # self._request_stats(ev.msg.datapath)
        self.change_tree()

        print("link delete")

        return

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("Switch enter")

        return

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)

        ''' for datapath in self.oldDataPath():
            if datapath == ev.msg.datapath:
                self.oldDataPath.remove(datapath)
            else:
                self.del_flow(datapath, 1)
                '''
        self.change_tree()
        #TODO
        self.oldDataPath.pop(ev.switch.dp.id)
        print("Switch leave")
        print(ev.switch)
        # print(ev.msg.datapath)
        return

    @set_ev_cls(event.EventSwitchReconnected)
    def _event_switch_reconnected_handler(self, ev):
        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        tree_old = self.create_tree()
        ''' for datapath in self.oldDataPath():
            if datapath == ev.msg.datapath:
                self.oldDataPath.remove(datapath)
            else:
                self.del_flow(datapath, 1)
                '''
        self.change_tree()
        print("Switch reconnected")
        # print(ev.msg.datapath)
        return

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()
        print("host add")

        return

    @set_ev_cls(event.EventHostMove)
    def _event_host_add_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("host move")

        return

    @set_ev_cls(event.EventHostDelete)
    def _event_host_delete_handler(self, ev):
        # for switch in get_all_switch(self):

        # msg = ev.switch.to_dict()
        # self._rpc_broadcall('event_switch_enter', msg)
        '''for datapath in self.oldDataPath():
            self.del_flow(datapath, 1)
        print(ev)
        # self._request_stats(ev.msg.datapath)'''
        self.change_tree()

        print("host add")

        return
    def __init__(self, *args, **kwargs):
        super(HopByHopSwitch, self).__init__(*args, **kwargs)
        self.tree_old = {}
        self.oldDataPath = {}
        self.nodesAndPort = {}

    # tutti i pacchetti al controllore
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Switch: " + str(ev.msg.datapath.id) + "----CONFIG_DISPATCHER")
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

    # trova switch destinazione e porta dello switch
    def find_destination_switch(self, destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #print("Switch: " + str(ev.msg.datapath.id) + "----MAIN_DISPATCHER")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst

        # se ARP esegui proxy arp
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.proxy_arp(msg)
            return

        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return
        if (len(self.tree_old) == 0):
            self.tree_old = self.create_tree()
            # print edges
            print(self.tree_old.edges.data())
            self.nodesAndPort = {}
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
        # match = parser.OFPMatch(eth_dst=dst,eth_src=eth.src)
        match = parser.OFPMatch(in_port=in_port)

        actions = []
        # print("Test")
        #print("SWITCH: " + str(datapath.id))
        # print("Info:   ")
        # print(nodesAndPort)
        try:
            for (port) in self.nodesAndPort[str(datapath.id)]:

                if (int(port) != in_port):
                    # print("Ports cazzo: " + str(port))
                    actions.append(parser.OFPActionOutput(int(port)))
        except:
            print()

        destination_mac = eth.dst

        # trova switch destinazione
        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)
        # print(dst_dpid)
        for host in get_all_host(self):
            if host.port.dpid == datapath.id:
                if (host.port.port_no != in_port):
                    actions.append(parser.OFPActionOutput(int(host.port.port_no)))

        # TODO: check this if
        '''if dst_dpid is None:
            print("Not ffffffffffffffff\n")
            # print "DP: ", datapath.id, "Host not found: ", pkt_ip.dst
            return
        '''
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

    def proxy_arp(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt_in = packet.Packet(msg.data)
        eth_in = pkt_in.get_protocol(ethernet.ethernet)
        arp_in = pkt_in.get_protocol(arp.arp)

        # gestiamo solo i pacchetti ARP REQUEST
        if arp_in.opcode != arp.ARP_REQUEST:
            return

        destination_host_mac = None

        for host in get_all_host(self):
            if arp_in.dst_ip in host.ipv4:
                destination_host_mac = host.mac
                break

        # host non trovato
        if destination_host_mac is None:
            # print("Non trovato")
            return

        pkt_out = packet.Packet()
        eth_out = ethernet.ethernet(
            dst=eth_in.src,
            src=destination_host_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        )
        arp_out = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=destination_host_mac,
            src_ip=arp_in.dst_ip,
            dst_mac=arp_in.src_mac,
            dst_ip=arp_in.src_ip
        )
        pkt_out.add_protocol(eth_out)
        pkt_out.add_protocol(arp_out)
        pkt_out.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=pkt_out.data
        )
        datapath.send_msg(out)
        return
