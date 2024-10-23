from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, icmp
from ryu.lib.packet import tcp, udp
from ryu.lib.packet import ether_types
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Threshold for detecting port scans
    PORT_SCAN_THRESHOLD = 2  # Unique ports
    TIME_WINDOW = 60  # Time window in seconds to detect scanning

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.scan_tracker = {}  # To track source IP and accessed ports with timestamps

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    def detect_port_scan(self, src_ip, dst_port):
        current_time = time.time()

        # Initialize tracking for new source IPs
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {'ports': set(), 'timestamps': []}

        # Track accessed port and timestamp
        self.scan_tracker[src_ip]['ports'].add(dst_port)
        self.scan_tracker[src_ip]['timestamps'].append(current_time)

        # Remove old timestamps (outside the time window)
        self.scan_tracker[src_ip]['timestamps'] = [t for t in self.scan_tracker[src_ip]['timestamps']
                                                   if current_time - t <= self.TIME_WINDOW]

        # Check if the number of unique ports exceeds the threshold
        if len(self.scan_tracker[src_ip]['ports']) > self.PORT_SCAN_THRESHOLD:
            return True
        return False

    def block_ip(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

        actions = []  # No actions to drop the packets

        priority = 50000
        self.add_flow(datapath, priority, match, actions)

        # Send an empty PacketOut to the switch to flush buffer
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=[], data=None)
        datapath.send_msg(out)

        self.logger.info(f"Blocking IP {src_ip} with drop rule.")

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
            return  # Ignore IPv6 packets

        # Learn a mac address to avoid FLOOD next time.
        dpid = datapath.id
        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if pkt.get_protocol(icmp.icmp):
            # Handle ICMP traffic, but install a flow ONLY for ICMP
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            else:
                self.add_flow(datapath, 1, match, actions)
        else:
            # If packet is IPv4, check for port scanning
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt:
                src_ip = ipv4_pkt.src
                dst_ip = ipv4_pkt.dst

                # Check for TCP or UDP protocol
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)

                if tcp_pkt:
                    dst_port = tcp_pkt.dst_port
                    if self.detect_port_scan(src_ip, dst_port):
                        self.block_ip(datapath, src_ip)
                        return
                elif udp_pkt:
                    dst_port = udp_pkt.dst_port
                    if self.detect_port_scan(src_ip, dst_port):
                        self.block_ip(datapath, src_ip)
                        return

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
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
