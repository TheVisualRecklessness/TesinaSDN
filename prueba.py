from scapy.all import sendp, Ether, IP, UDP
pkt = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=12345, dport=80)
sendp(pkt, iface='h1-eth0', verbose=True)
