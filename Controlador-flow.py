from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, tcp, udp
import time
from collections import defaultdict
import threading

class CombinedController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    PORT_SCAN_THRESHOLD = 4
    TIME_WINDOW = 60
    FLOW_LIMIT = 12

    def __init__(self, *args, **kwargs):
        super(CombinedController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.scan_tracker = {}
        self.blocked_ips = {}
        self.blocked_ports = {}
        self.dps = {}
        self.flow_counter = defaultdict(int)
        self.flow_per_ip_counter = defaultdict(int)
        self.start_timer()

    def start_timer(self):
        self.logger.info("Direcciones IP bloqueadas: ")
        for ip in self.blocked_ips:
            self.logger.info(ip)
        self.logger.info("Puertos fisicos de switch bloqueados: ")
        for port in self.blocked_ports:
            self.logger.info(f"Puerto {port}")
        self.request_flow_stats()
        threading.Timer(15, self.start_timer).start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def get_match_field(self, match, field_name):
        match_dict = match.to_jsondict()['OFPMatch']['oxm_fields']
        for field in match_dict:
            if field['OXMTlv']['field'] == field_name:
                return field['OXMTlv']['value']
        return None
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[datapath.id] = datapath
        elif ev.state == 'DEAD_DISPATCHER':
            if datapath.id in self.dps:
                del self.dps[datapath.id]

    def get_match_field(self, match, field_name):
        match_dict = match.to_jsondict()['OFPMatch']['oxm_fields']
        for field in match_dict:
            if field['OXMTlv']['field'] == field_name:
                return field['OXMTlv']['value']
        return None

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        dpid = datapath.id
        tcp_dst = self.get_match_field(match, 'tcp_dst')
        udp_dst = self.get_match_field(match, 'udp_dst')
        dst_ip = self.get_match_field(match, 'ipv4_dst')

        # if dst_ip in self.flow_per_ip_counter and self.flow_per_ip_counter[dst_ip] >= self.FLOW_LIMIT:
        #     self.logger.info(f"Flujo máximo alcanzado para dirección IP {dst_ip}. No se instalarán más flujos.")
        #     return

        if tcp_dst and tcp_dst > 49151:
            self.logger.info(f"Flujo con puerto destino en rango de puertos efimeros. No se instala.")
            return
        elif udp_dst and udp_dst > 49151:
            self.logger.info(f"Flujo con puerto destino en rango de puertos efimeros. No se instala.")
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

        if dst_ip:
            self.flow_per_ip_counter[dst_ip] += 1
            self.logger.info(f'Flujos por IP destino {dst_ip}: {self.flow_per_ip_counter[dst_ip]}')
            if self.flow_per_ip_counter[dst_ip] >= self.FLOW_LIMIT:
                self.logger.info(f"Flujo maximo alcanzado para dirección IP {dst_ip}. No se instalan mas flujos.")
                self.block_port(datapath, 5)
                return
    def request_flow_stats(self):
        for dp in self.dps.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            req = parser.OFPFlowStatsRequest(dp)
            dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('Switch           '
                        'puerto_salida paquetes  bytes')
        self.logger.info('---------------- '
                        '------------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                        key=lambda flow: (flow.match.get('in_port', -1),
                                            flow.match.get('eth_dst', ''))):
            self.logger.info('%016x %8x %8d %8d',
                            ev.msg.datapath.id,
                            stat.instructions[0].actions[0].port,
                            stat.packet_count, stat.byte_count)

    def detect_port_scan(self, src_ip, dst_port):
        current_time = time.time()
    
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {'port_timestamps': []}
    
        if dst_port not in range(49152, 65535):
            self.scan_tracker[src_ip]['port_timestamps'].append({'port': dst_port, 'timestamp': current_time})

            self.scan_tracker[src_ip]['port_timestamps'] = [
                entry for entry in self.scan_tracker[src_ip]['port_timestamps']
                if current_time - entry['timestamp'] <= self.TIME_WINDOW
            ]

            ports = {entry['port'] for entry in self.scan_tracker[src_ip]['port_timestamps']}
    
            self.logger.info(f"Direccion IP origen {src_ip} ha accesado {len(ports)} puertos.")
            self.logger.info(f"Direccion IP origen {src_ip} ha accesado los puertos: {ports}")
            if len(ports) > self.PORT_SCAN_THRESHOLD:
                return True
            return False

    def block_port(self, datapath, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(in_port=in_port)

        actions = []

        priority = 50000
        self.add_flow(datapath, priority, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=[], data=None)
        datapath.send_msg(out)

        self.logger.info(f"Bloqueando puerto {in_port} por posible ataque de inundacion.")
        self.blocked_ports[in_port] = True
    
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

        self.logger.info(f"Bloqueando direccion IP {src_ip} por posible escaneo de puertos.")
        self.blocked_ips[src_ip] = True

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
            # icmp_pkt = pkt.get_protocol(icmp.icmp)

            # if icmp_pkt:
            #     match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_src=src_ip)
            #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #     else:
            #         self.add_flow(datapath, 1, match, actions)
            
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
                self.logger.info(f"Paquete entrante con puerto TCP destino: {dst_port}.")
                if self.detect_port_scan(src_ip, dst_port):
                    self.block_ip(datapath, src_ip)
                    return
                else:
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=dst_ip, tcp_dst=dst_port)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath, 1, match, actions)
            elif udp_pkt:
                dst_port = udp_pkt.dst_port
                self.logger.info(f"Paquete entrante con puerto UDP destino: {dst_port}.")
                if self.detect_port_scan(src_ip, dst_port):
                    self.block_ip(datapath, src_ip)
                    return
                else:
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=dst_ip, udp_dst=dst_port)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
