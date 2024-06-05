# detection.py

from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import scapy.all as scapy
from config import *
import tkinter as tk
from enum import Enum, auto

class State(Enum):
    IDLE = auto()
    SUSPICIOUS = auto()
    ATTACK = auto()

class StateMachine:
    def __init__(self):
        self.state = State.IDLE
        self.last_activity_time = datetime.now()

    def transition(self, new_state):
        if self._is_valid_transition(new_state):
            print(f"Transitioning from {self.state} to {new_state}")
            self.state = new_state
            self.last_activity_time = datetime.now()
        else:
            if self.state == new_state:
                print(f"Maintaining state {self.state}")
                self.last_activity_time = datetime.now()
            else:
                print(f"Invalid transition from {self.state} to {new_state}")

    def _is_valid_transition(self, new_state):
        valid_transitions = {
            State.IDLE: [State.SUSPICIOUS, State.IDLE],
            State.SUSPICIOUS: [State.ATTACK, State.SUSPICIOUS],
            State.ATTACK: [State.IDLE, State.ATTACK],
        }
        return new_state in valid_transitions[self.state]

state_machine = StateMachine()

def log_intrusion(message, packet=None, tag=None, text_area=None, gui=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - {message}"
    if packet:
        log_message += f" | Packet Info: {packet.summary()}"

    logging.info(log_message)
    with open(suspicious_log_file, "a") as f:
        f.write(log_message + '\n')

    if text_area:
        if tag:
            text_area.insert(tk.END, log_message + '\n', tag)
        else:
            text_area.insert(tk.END, log_message + '\n')
        text_area.yview(tk.END)
        if gui:
            gui.intrusion_count += 1
            gui.intrusion_count_label.config(text=f"Intrusiones Detectadas: {gui.intrusion_count}")

def analyze_packet(packet, text_area, gui=None):
    try:
        current_time = datetime.now()
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            if packet.haslayer(scapy.TCP):
                dst_port = packet[scapy.TCP].dport
                flags = packet[scapy.TCP].flags

                # Estado SUSPICIOUS: Acceso a puerto sospechoso
                if dst_port in SUSPICIOUS_PORTS:
                    state_machine.transition(State.SUSPICIOUS)
                    log_intrusion(f"Acceso a puerto sospechoso detectado: {src_ip} -> {dst_ip}:{dst_port}", packet, tag='suspicious_port', text_area=text_area, gui=gui)

                # Estado ATTACK: Intentos fallidos de inicio de sesión (ejemplo usando el puerto 22 para SSH)
                if dst_port == 22 and flags == "R":
                    failed_login_attempts[src_ip] += 1
                    if failed_login_attempts[src_ip] > FAILED_LOGIN_ATTEMPTS_THRESHOLD:
                        state_machine.transition(State.ATTACK)
                        log_intrusion(f"Se detectaron múltiples intentos fallidos de inicio de sesión desde {src_ip}", packet, tag='failed_login', text_area=text_area, gui=gui)

                # Estado SUSPICIOUS: Detección de escaneo de puertos
                port_scans[src_ip] = [t for t in port_scans[src_ip] if t > current_time - timedelta(seconds=10)]
                port_scans[src_ip].append(current_time)
                if len(port_scans[src_ip]) > PORT_SCAN_THRESHOLD:
                    state_machine.transition(State.SUSPICIOUS)
                    log_intrusion(f"Se detectó escaneo de puertos desde {src_ip}", packet, tag='port_scan', text_area=text_area, gui=gui)

                # Estado ATTACK: Detección de SYN flood
                if flags == "S":
                    last_syn_time[src_ip] = current_time
                    syn_flood_attempts[src_ip] += 1
                    if syn_flood_attempts[src_ip] > SYN_FLOOD_THRESHOLD:
                        state_machine.transition(State.ATTACK)
                        log_intrusion(f"Se detectó SYN flood desde {src_ip}", packet, tag='syn_flood', text_area=text_area, gui=gui)
                elif flags == "A":
                    syn_flood_attempts[src_ip] = max(0, syn_flood_attempts[src_ip] - 1)

            # Estado ATTACK: Detección de DDoS
            ddos_detection_window.append(current_time)
            while ddos_detection_window and current_time - ddos_detection_window[0] > timedelta(seconds=1):
                ddos_detection_window.popleft()
            if len(ddos_detection_window) > DDOS_THRESHOLD:
                state_machine.transition(State.ATTACK)
                log_intrusion(f"Posible ataque DDoS detectado desde múltiples IPs", packet, tag='ddos', text_area=text_area, gui=gui)

        # Resetear al estado IDLE si no hay actividad sospechosa después de un tiempo
        if state_machine.state == State.SUSPICIOUS or state_machine.state == State.ATTACK:
            if current_time - state_machine.last_activity_time > timedelta(seconds=10):
                state_machine.transition(State.IDLE)

    except Exception as e:
        log_intrusion(f"Error analizando paquete: {e}", text_area=text_area, gui=gui)
