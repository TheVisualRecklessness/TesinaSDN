def malicious_ports():
    return {
        '80': True,
        '443': True,
        '21': True,
        '22': True,
        '23': True,
    }

def malicious_ips():
    return {
        '10.0.0.3': True,
    }

def malicious_macs():
    return {
        'AA:BB:CC:DD:EE:FF': True,
    }