from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, inet
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, icmp, tcp, udp
from collections import defaultdict

class CombinedController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CombinedController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_counter = defaultdict(int)  # Contador para flujos instalados por switch

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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        # Aumentar el contador de flujos instalados por el switch
        self.flow_counter[datapath.id] += 1
        self.logger.info(f"Inicio de flujos instalados {datapath.id}. Total de flujos: {self.flow_counter[datapath.id]}")

        # Limitar el número de flujos para prevenir ataques de inundación
        if self.flow_counter[datapath.id] > 1000:
            self.logger.warning(f"limite de flujos superado {datapath.id}. no se instaln mas flujos.")
            # Implementar lógica para evitar instalar más flujos si se supera el límite

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Evitar instalar reglas para paquetes LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Manejo de paquetes ICMP, TCP y UDP
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                self.logger.info("ICMP packet detected.")
                # Puedes agregar lógica específica si quieres manejar los paquetes ICMP

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Guardar la MAC de origen en la tabla
        self.mac_to_port[dpid][src] = in_port

        # Verificar si la MAC de destino está en la tabla
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Añadir la regla de flujo si no estamos inundando
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Enviar el paquete a la salida correcta
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

