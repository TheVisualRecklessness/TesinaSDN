from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

class PortScanDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortScanDetection, self).__init__(*args, **kwargs)
        self.port_scan_threshold = 10  # Threshold for port scan
        self.scan_data = {}  # Dictionary to track scanning behavior
        self.time_window = 60  # Time window in seconds

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not ip_pkt:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        dst_port = None

        if tcp_pkt:
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            dst_port = udp_pkt.dst_port

        if dst_port:
            self.detect_port_scan(src_ip, dst_ip, dst_port)

    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        if src_ip not in self.scan_data:
            self.scan_data[src_ip] = set()

        self.scan_data[src_ip].add(dst_port)

        if len(self.scan_data[src_ip]) > self.port_scan_threshold:
            self.logger.info("Potential port scanning detected from %s", src_ip)

    def block_traffic(self, src_ip):
        pass
