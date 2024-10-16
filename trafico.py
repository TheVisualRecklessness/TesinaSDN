import random
from scapy.all import IP, TCP, send

ip_range = ['10.0.0.1', '10.0.0.2']
tcp_ports = [80, 443, 21, 22, 23, 25, 69, 109, 110, 119]

def generate_random_packet():
    dst_ip = random.choice(ip_range)
    dst_port = random.choice(tcp_ports)
    
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
    return packet

for _ in range(10):
    packet = generate_random_packet()
    send(packet)