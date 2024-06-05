import logging
from collections import defaultdict, deque
from datetime import datetime

# Configurar el registro de actividades
logging.basicConfig(filename="intrusion_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")
suspicious_log_file = "suspicious_intrusions.txt"

# Configuraciones por defecto
SUSPICIOUS_PORTS = [23, 2323, 3389]  # Telnet, Telnet alternativo, RDP
FAILED_LOGIN_ATTEMPTS_THRESHOLD = 5  # Umbral de intentos fallidos de inicio de sesión
PORT_SCAN_THRESHOLD = 10  # Número de puertos diferentes accedidos en un corto periodo de tiempo
SYN_FLOOD_THRESHOLD = 100  # Número de paquetes SYN sin ACK correspondientes
DDOS_THRESHOLD = 1000  # Número de paquetes por segundo que indica un posible ataque DDoS

# Diccionarios para rastrear actividades sospechosas
failed_login_attempts = defaultdict(int)
port_scans = defaultdict(list)
syn_flood_attempts = defaultdict(int)
ddos_detection_window = deque(maxlen=DDOS_THRESHOLD)
last_syn_time = defaultdict(datetime)

# Autenticación
USERNAME = "admin"
PASSWORD = "admin"
