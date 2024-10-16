import random
import logging
from scapy.all import IP, TCP, send

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

ip_range = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
tcp_ports = [80, 443, 21, 22, 23, 25, 69, 109, 110, 119]

def generate_random_packet():
    dst_ip = random.choice(ip_range)
    dst_port = random.choice(tcp_ports)
    src_port = random.randint(49152, 65535)
    
    packet = IP(dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    
    
    logging.info(f'Enviando paquete: {packet.summary()}')
    
    return packet

for _ in range(10):
    packet = generate_random_packet()
    send(packet)