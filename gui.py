# gui.py

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Menu
from tkinter import ttk as ttk
from threading import Thread, Event
from config import *
from detection import log_intrusion, analyze_packet
import scapy.all as scapy
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
from auth import log_user_info

class IntrusionDetectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Detección de Intrusiones")
        self.root.geometry("1000x750")
        self.root.iconbitmap("./icons/dtbcode.ico")  # Añadir el ícono de la aplicación
        self.style = ttk.Style('darkly')

        self.sniffing = False
        self.packet_count = 0
        self.intrusion_count = 0
        self.stop_sniffing_event = Event()

        # Inicializa widgets antes de autenticar
        self.create_widgets()

        if not self.authenticate():
            self.root.destroy()
            return

    def create_widgets(self):
        # Create menu bar
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Exportar Log", command=self.export_log)
        file_menu.add_command(label="Salir", command=self.root.quit)

        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Acerca de", command=self.show_about_info)

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Estado: Listo", anchor=tk.W, bootstyle="dark")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Text area for logging
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30, font=("Consolas", 12),
                                                   bg="#1e1e1e", fg="#dcdcdc", insertbackground="#dcdcdc")
        self.text_area.pack(padx=10, pady=10)

        # Buttons with icons
        button_frame = ttk.Frame(self.root, padding=10, bootstyle="dark")
        button_frame.pack(pady=10)

         # Load icons
        self.start_icon = ImageTk.PhotoImage(Image.open("./icons/start.png").resize((20, 20)))
        self.stop_icon = ImageTk.PhotoImage(Image.open("./icons/stop.png").resize((20, 20)))
        self.config_icon = ImageTk.PhotoImage(Image.open("./icons/config.png").resize((20, 20)))

        self.start_button = ttk.Button(button_frame, text="Iniciar", image=self.start_icon, compound=tk.LEFT,
                                       command=self.start_sniffing, bootstyle=SUCCESS, width=12)
        self.start_button.grid(row=0, column=0, padx=10)
        self.start_button.bind("<Enter>", lambda e: self.update_status("Iniciar captura de paquetes"))
        self.start_button.bind("<Leave>", lambda e: self.update_status(""))

        self.stop_button = ttk.Button(button_frame, text="Detener", image=self.stop_icon, compound=tk.LEFT,
                                      command=self.stop_sniffing, bootstyle=DANGER, width=12)
        self.stop_button.grid(row=0, column=1, padx=10)
        self.stop_button.bind("<Enter>", lambda e: self.update_status("Detener captura de paquetes"))
        self.stop_button.bind("<Leave>", lambda e: self.update_status(""))

        self.config_button = ttk.Button(button_frame, text="Configurar", image=self.config_icon, compound=tk.LEFT,
                                        command=self.configure_settings, bootstyle=INFO, width=12)
        self.config_button.grid(row=0, column=2, padx=10)
        self.config_button.bind("<Enter>", lambda e: self.update_status("Configurar sistema"))
        self.config_button.bind("<Leave>", lambda e: self.update_status(""))

        # Dashboard frame
        dashboard_frame = ttk.Frame(self.root, padding=20, bootstyle="dark")
        dashboard_frame.pack(pady=20)

        self.packet_count_label = ttk.Label(dashboard_frame, text="Paquetes Capturados: 0", font=("Arial", 14), bootstyle="dark")
        self.packet_count_label.grid(row=0, column=0, padx=20)

        self.intrusion_count_label = ttk.Label(dashboard_frame, text="Intrusiones Detectadas: 0", font=("Arial", 14), bootstyle="dark")
        self.intrusion_count_label.grid(row=0, column=1, padx=20)

    def authenticate(self):
        login_window = ttk.Toplevel(self.root)
        login_window.title("Login")
        login_window.geometry("300x300")

        ttk.Label(login_window, text="Username:", font=("Arial", 12)).pack(pady=5)
        username_entry = ttk.Entry(login_window, font=("Arial", 12))
        username_entry.pack(pady=5)

        ttk.Label(login_window, text="Password:", font=("Arial", 12)).pack(pady=5)
        password_entry = ttk.Entry(login_window, font=("Arial", 12), show="*")
        password_entry.pack(pady=5)

        def check_credentials():
            username = username_entry.get()
            password = password_entry.get()
            if username == USERNAME and password == PASSWORD:
                log_user_info(self.text_area)
                login_window.destroy()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
                login_window.destroy()
                self.root.destroy()

        ttk.Button(login_window, text="Login", command=check_credentials, bootstyle=PRIMARY).pack(pady=10)
        self.root.wait_window(login_window)
        return self.root.winfo_exists()

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.stop_sniffing_event.clear()
            self.sniff_thread = Thread(target=self.sniff_packets)
            self.sniff_thread.start()
            self.update_status("Captura de paquetes iniciada")
            self.log_intrusion("Iniciando captura de paquetes...")

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.stop_sniffing_event.set()
            self.sniff_thread.join()
            self.update_status("Captura de paquetes detenida")
            self.log_intrusion("Deteniendo captura de paquetes.")

    def sniff_packets(self):
        try:
            scapy.sniff(prn=self.process_packet, store=False, stop_filter=lambda x: self.stop_sniffing_event.is_set())
        except Exception as e:
            self.log_intrusion(f"Error al capturar paquetes: {e}")

    def process_packet(self, packet):
        self.packet_count += 1
        self.root.after(0, self.packet_count_label.config, {'text': f"Paquetes Capturados: {self.packet_count}"})
        analyze_packet(packet, self.text_area, gui=self)

    def configure_settings(self):
        try:
            global SUSPICIOUS_PORTS, FAILED_LOGIN_ATTEMPTS_THRESHOLD, PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD, DDOS_THRESHOLD

            new_suspicious_ports = simpledialog.askstring("Puertos Sospechosos",
                                                          "Ingrese los puertos sospechosos separados por comas:",
                                                          initialvalue=",".join(map(str, SUSPICIOUS_PORTS)))
            if new_suspicious_ports:
                SUSPICIOUS_PORTS = list(map(int, new_suspicious_ports.split(",")))

            new_failed_login_attempts_threshold = simpledialog.askinteger("Umbral de Intentos Fallidos",
                                                                          "Ingrese el umbral de intentos fallidos de inicio de sesión:",
                                                                          initialvalue=FAILED_LOGIN_ATTEMPTS_THRESHOLD)
            if new_failed_login_attempts_threshold is not None:
                FAILED_LOGIN_ATTEMPTS_THRESHOLD = new_failed_login_attempts_threshold

            new_port_scan_threshold = simpledialog.askinteger("Umbral de Escaneo de Puertos",
                                                              "Ingrese el umbral de escaneo de puertos:",
                                                              initialvalue=PORT_SCAN_THRESHOLD)
            if new_port_scan_threshold is not None:
                PORT_SCAN_THRESHOLD = new_port_scan_threshold

            new_syn_flood_threshold = simpledialog.askinteger("Umbral de SYN Flood", "Ingrese el umbral de SYN flood:",
                                                              initialvalue=SYN_FLOOD_THRESHOLD)
            if new_syn_flood_threshold is not None:
                SYN_FLOOD_THRESHOLD = new_syn_flood_threshold

            new_ddos_threshold = simpledialog.askinteger("Umbral de DDoS", "Ingrese el umbral de DDoS (paquetes por segundo):",
                                                         initialvalue=DDOS_THRESHOLD)
            if new_ddos_threshold is not None:
                DDOS_THRESHOLD = new_ddos_threshold

            self.update_status("Configuración actualizada")
            self.log_intrusion("Configuración actualizada.")

        except Exception as e:
            self.log_intrusion(f"Error al configurar ajustes: {e}")

    def show_about_info(self):
        messagebox.showinfo("Acerca de", "Sistema de Detección de Intrusiones\nVersión 2.0\nDesarrollado por DTBCODE")

    def update_status(self, status):
        if status:
            self.status_bar.config(text=f"Estado: {status}")
        else:
            self.status_bar.config(text="Estado: Listo")
        self.root.update_idletasks()

    def export_log(self):
        try:
            with open(suspicious_log_file, 'r') as f:
                logs = f.read()
            with open("exported_logs.txt", 'w') as f:
                f.write(logs)
            messagebox.showinfo("Exportar Log", "El log se ha exportado correctamente a 'exported_logs.txt'.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar el log: {e}")

    def log_intrusion(self, message):
        self.root.after(0, log_intrusion, message, text_area=self.text_area, gui=self)
