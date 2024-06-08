# Creado por DTBCODE / 2024

import logging
from collections import defaultdict, deque
from datetime import datetime
import os
from logging.handlers import RotatingFileHandler

# Crear directorio Logs si no existe
LOG_DIR = "Logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configurar el registro de actividades con rotación de archivos
log_handler = RotatingFileHandler(os.path.join(LOG_DIR, "intrusion_log.txt"), maxBytes=1000000, backupCount=5)
logging.basicConfig(handlers=[log_handler], level=logging.INFO, format="%(asctime)s - %(message)s")

# Archivo de registros de intrusiones sospechosas
suspicious_log_file = os.path.join(LOG_DIR, "suspicious_intrusions.txt")

# Configuración de la base de datos
DATABASE_PATH = os.path.join(LOG_DIR, "auth_logs.db")

# Configuraciones por defecto para la detección de intrusos
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

# Credenciales de autenticación
USERNAME = os.getenv('APP_USERNAME', 'admin')
PASSWORD = os.getenv('APP_PASSWORD', 'admin')
