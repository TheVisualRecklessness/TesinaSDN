from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, tcp, udp
import time
from collections import defaultdict

class CombinedController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    PORT_SCAN_THRESHOLD = 4
    TIME_WINDOW = 60
    FLOW_LIMIT = 1000

    def __init__(self, *args, **kwargs):
        super(CombinedController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.scan_tracker = {}
        self.flow_counter = defaultdict(int)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        dpid = datapath.id

        if self.flow_counter[dpid] >= self.FLOW_LIMIT:
            self.logger.info(f"Flujo máximo alcanzado en switch {dpid}. No se instalarán más flujos.")
            return
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        self.flow_counter[dpid] += 1
        self.logger.info(f"Flujo instalado en switch {dpid}. Número de flujos: {self.flow_counter[dpid]}")

    def detect_port_scan(self, src_ip, dst_port):
        current_time = time.time()

        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {'ports': set(), 'timestamps': []}

        if dst_port not in range(49152, 65535):
            self.scan_tracker[src_ip]['ports'].add(dst_port)
            self.scan_tracker[src_ip]['timestamps'].append(current_time)            

            self.scan_tracker[src_ip]['timestamps'] = [t for t in self.scan_tracker[src_ip]['timestamps']
                                                    if current_time - t <= self.TIME_WINDOW]

            self.logger.info(f"Dirección IP origen {src_ip} ha accesado {len(self.scan_tracker[src_ip]['ports'])} puertos.")
            self.logger.info(f"Dirección IP origen {src_ip} ha accesado los puertos: {self.scan_tracker[src_ip]['ports']}")
            if len(self.scan_tracker[src_ip]['ports']) > self.PORT_SCAN_THRESHOLD:
                return True
            return False

    def block_ip(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

        actions = []

        priority = 50000
        self.add_flow(datapath, priority, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=[], data=None)
        datapath.send_msg(out)

        self.logger.info(f"Bloqueando dirección IP {src_ip} por posible escaneo de puertos.")


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dpid = datapath.id
        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if icmp_pkt:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_src=src_ip)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                else:
                    self.add_flow(datapath, 1, match, actions)
            
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
                self.logger.info(f"Paquete entrante con puerto TCP destino: {dst_port}.")
                if self.detect_port_scan(src_ip, dst_port):
                    self.block_ip(datapath, src_ip)
                    return
            elif udp_pkt:
                dst_port = udp_pkt.dst_port
                self.logger.info(f"Paquete entrante con puerto UDP destino: {dst_port}.")
                if self.detect_port_scan(src_ip, dst_port):
                    self.block_ip(datapath, src_ip)
                    return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
