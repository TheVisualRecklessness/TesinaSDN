from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, inet
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, icmp, tcp, udp
from dataset import malicious_ports, malicious_ips, malicious_macs

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        self.send_flow_stats_request(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        tlpkt = 0

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        if eth.src in malicious_macs.keys():
            self.logger.info("Malicious MAC detected. Dropping packet.")
            match = parser.OFPMatch(eth_src=eth.src)
            self.add_flow(datapath, 1, match, [])
            return
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # if ip_pkt.src in malicious_ips.keys():
            #     self.logger.info("Malicious IP detected. Dropping packet.")
            #     match = parser.OFPMatch(ipv4_src=ip_pkt.src)
            #     self.add_flow(datapath, 1, match, [])
            #     return
        
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                self.logger.info("ICMP packet detected. Dropping packet.")
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1)
                self.add_flow(datapath, 1, match, [])
                return
        
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            tlpkt = tcp_pkt
            if str(tcp_pkt.dst_port) in malicious_ports.keys():
                self.logger.info(f'Malicious TCP port detected. Dropping packet. Port: {tcp_pkt.dst_port}')
                match = parser.OFPMatch(tcp_dst=tcp_pkt.dst_port)
                self.add_flow(datapath, 1, match, [])
                return
        
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            tlpkt = udp_pkt
            if str(udp_pkt.dst_port) in malicious_ports.keys():
                self.logger.info(f'Malicious UDP port detected. Dropping packet. Port: {udp_pkt.dst_port}')
                match = parser.OFPMatch(udp_dst=udp_pkt.dst_port)
                self.add_flow(datapath, 1, match, [])
                return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info(f'Packet sent to port {out_port} with TCP/UDP packet: {tlpkt}')

    def send_flow_stats_request(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

            # Extract destination transport layer port if available
            if 'ipv4_dst' in stat.match:
                ip_proto = stat.match.get('ip_proto')
                if ip_proto == inet.IPPROTO_TCP:
                    self.logger.info('TCP dst port: %d', stat.match.get('tcp_dst'))