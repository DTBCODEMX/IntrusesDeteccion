import psutil
import socket
from detection import log_intrusion

# Funciones para obtener IP, IPv6 y MAC
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))  # Conectar a una IP externa para obtener la IP local
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = 'N/A'
    finally:
        s.close()
    return ip_address

def get_ipv6_address():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET6 and not addr.address.startswith('fe80'):
                return addr.address
    return 'N/A'

def get_mac_address():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                return addr.address
    return 'N/A'

def log_user_info(text_area):
    ip_address = get_ip_address()
    ipv6_address = get_ipv6_address()
    mac_address = get_mac_address()
    log_intrusion(f"Usuario autenticado - IP: {ip_address}, IPv6: {ipv6_address}, MAC: {mac_address}", text_area=text_area)
