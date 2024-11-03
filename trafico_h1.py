import random
import logging
from scapy.all import IP, TCP, UDP, send

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

ip_range = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
tcp_ports = [20, 21, 22, 23, 25, 80, 110, 143, 443]
udp_ports = [53, 67, 68, 69, 123, 161, 162, 500]

def generate_random_packet():
    dst_ip = '10.0.0.1'
    dst_port = random.choice(tcp_ports)
    src_port = random.randint(49152, 65535)
    
    protocol = random.choice(['TCP', 'UDP'])

    if protocol == 'TCP':
        packet = IP(dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    else:
        packet = IP(dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
    
    logging.info(f'Enviando paquete: {packet.summary()}')
    
    return packet

for _ in range(10):
    packet = generate_random_packet()
    send(packet)