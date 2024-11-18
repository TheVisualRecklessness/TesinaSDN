import random
import logging
from scapy.all import IP, TCP, UDP, send

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

src_ip_range = ['140.25.7.4', '150.10.1.5', '160.42.67.124']
dst_ip_range = ['10.0.0.1', '10.0.0.2']
tcp_ports = [20, 21, 22, 23, 25, 80, 110, 143, 443]
udp_ports = [53, 67, 68, 69, 123, 161, 162, 500]

pkt_threshold = 100
pkt_count = 0
traffic_types = ['benign', 'malicious']

def benign_traffic():
    dst_ip = '10.0.0.4'
    src_ip = '145.127.15.12'
    dst_port = 443
    src_port = random.randint(49152, 65535)

    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    logging.info(f'Enviando paquete: {packet.summary()}')

    return packet

def generate_random_packet():
    dst_ip = random.choice(dst_ip_range)
    src_ip = random.choice(src_ip_range)
    dst_port = random.choice(tcp_ports)
    src_port = random.randint(49152, 65535)
    
    protocol = random.choice(['TCP', 'UDP'])

    if protocol == 'TCP':
        packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    else:
        packet = IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
    
    logging.info(f'Enviando paquete: {packet.summary()}')
    
    return packet

while pkt_count < pkt_threshold:
    traffic = random.choice(traffic_types)
    if traffic == 'benign':
        pkt = benign_traffic()
    else:
        pkt = generate_random_packet()
    send(pkt)
    pkt_count += 1