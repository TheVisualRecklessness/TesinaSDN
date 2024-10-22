from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp
from collections import defaultdict
import time

class AntiFlowFloodingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AntiFlowFloodingController, self).__init__(*args, **kwargs)
        # Diccionario para rastrear el número de flujos por IP de origen
        self.flow_count = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})
        self.FLOW_LIMIT = 100  # Límite de flujos permitidos por IP de origen
        self.TIME_WINDOW = 60  # Tiempo de ventana (segundos) para contar los flujos

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Función que se llama al conectar un switch
        self.logger.info("Anti-flow flooding controller initialized")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Función que maneja los paquetes que no tienen una regla en la tabla de flujo
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extraer el paquete
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Filtrar solo paquetes IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst

        # Verificar si la IP de origen ha superado el límite de flujos permitidos
        if self.is_flow_limit_exceeded(ip_src):
            self.logger.warning(f"Rate limiting applied to IP: {ip_src}")
            return  # Descarta el paquete y no instala el flujo

        # Instalamos la regla de flujo para este paquete si no ha superado el límite
        self.add_flow(datapath, in_port, eth, ip_pkt)

    def is_flow_limit_exceeded(self, ip_src):
        # Verificar si la IP de origen ha excedido el límite de flujos permitidos
        current_time = time.time()
        if current_time - self.flow_count[ip_src]['timestamp'] > self.TIME_WINDOW:
            # Reiniciar el contador si el tiempo de la ventana ha expirado
            self.flow_count[ip_src] = {'count': 1, 'timestamp': current_time}
            return False
        else:
            # Incrementar el contador de flujos
            self.flow_count[ip_src]['count'] += 1
            # Si el límite de flujos ha sido excedido, denegar el paquete
            if self.flow_count[ip_src]['count'] > self.FLOW_LIMIT:
                return True
            return False

    def add_flow(self, datapath, in_port, eth, ip_pkt, idle_timeout=10, hard_timeout=30):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Crear coincidencia (match) para el flujo con las direcciones IP y MAC
        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=eth.src,
            eth_dst=eth.dst,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst
        )

        # Definir las acciones (ej. enviar al puerto)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # Instrucción para aplicar las acciones
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Definir el modificador de flujo con timeouts para evitar sobrecarga de reglas
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=1, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout
        )

        # Enviar el flujo al switch
        datapath.send_msg(mod)
        self.logger.info(f"Flow added: IP src: {ip_pkt.src}, IP dst: {ip_pkt.dst}")
