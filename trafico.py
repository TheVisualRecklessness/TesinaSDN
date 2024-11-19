import random
import logging
from scapy.all import IP, TCP, UDP, send

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

src_ip_range = ['140.25.7.4', '150.10.1.5', '160.42.67.124', '190.53.108.60', '181.50.43.21']
benign_src_ip = ['145.127.15.12', '100.103.29.63', '98.53.23.100', '156.74.102.78']
dst_ip_range = ['10.0.0.1', '10.0.0.2']
tcp_ports = [20, 21, 22, 23, 25, 80, 110, 143, 443]
udp_ports = [53, 67, 68, 69, 123, 161, 162, 500]

pkt_threshold = 5
pkt_count = 0
traffic_types = ['benign', 'malicious']
benign_pkts = 0
malicious_pkts = 0

def benign_traffic(pkt_count):
    dst_ip = '10.0.0.4'
    src_ip = random.choice(benign_src_ip)
    dst_port = 443
    src_port = random.randint(49152, 65535)

    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    logging.info(f'Enviando paquete: {packet.summary()}')
    logging.info(f'Paquete No. {pkt_count} enviado. Tamano: {len(packet)}')

    return packet

def generate_random_packet(pkt_count):
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
    logging.info(f'Paquete No. {pkt_count} enviado.')
    
    return packet

while pkt_count < pkt_threshold:
    #traffic = random.choice(traffic_types)
    traffic = 'malicious'
    if traffic == 'benign':
        pkt = benign_traffic(pkt_count)
        benign_pkts += 1
    else:
        pkt = generate_random_packet(pkt_count)
        malicious_pkts += 1
    send(pkt)
    pkt_count += 1

logging.info(f'Paquetes benignos enviados: {benign_pkts}')
logging.info(f'Paquetes maliciosos enviados: {malicious_pkts}')