import flet as ft
from threading import Thread, Event
from config import *
from detection import log_intrusion, analyze_packet
import scapy.all as scapy
from auth import log_user_info

class LoginWindow(ft.UserControl):
    def __init__(self, switch_to_detection):
        super().__init__()
        self.switch_to_detection = switch_to_detection

    def build(self):
        self.username_input = ft.TextField(
            label="Username",
            border_radius=8,
            color="white",
            bgcolor="purple"
        )
        self.password_input = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            border_radius=8,
            color="white",
            bgcolor="purple"
        )
        return ft.Column(
            [
                ft.Text("Intrusion Detection System", size=30, color="purple"),
                self.username_input,
                self.password_input,
                ft.ElevatedButton(
                    text="Login",
                    on_click=self.check_credentials,
                    bgcolor="black",
                    color="purple",
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=8),
                        animation_duration=300
                    )
                )
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
        )

    def check_credentials(self, e):
        if self.username_input.value == USERNAME and self.password_input.value == PASSWORD:
            log_user_info(None)
            self.switch_to_detection()
        else:
            self.page.snack_bar = ft.SnackBar(ft.Text("Invalid username or password", color="red"))
            self.page.snack_bar.open = True
            if self.page:  # Verificar si self.page no es None
                self.page.update()

class DetectionWindow(ft.UserControl):
    def __init__(self):
        super().__init__()
        self.sniffing = False
        self.packet_count = 0
        self.intrusion_count = 0
        self.stop_sniffing_event = Event()
        self.page = None

    def build(self):
        self.page = self.page
        self.log_area = ft.Column(scroll=ft.ScrollMode.AUTO)
        self.packet_count_label = ft.Text("Paquetes Capturados: 0", color="white", expand=True, size=20)
        self.intrusion_count_label = ft.Text("Intrusiones Detectadas: 0", color="white", expand=True, size=20)
        self.start_button = ft.ElevatedButton(
            text="Iniciar",
            on_click=self.start_sniffing_clicked,
            bgcolor="black",
            color="purple",
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                animation_duration=300
            )
        )
        return ft.Column(
            [
                ft.Row([self.packet_count_label, self.intrusion_count_label], alignment=ft.MainAxisAlignment.START),
                ft.Container(self.log_area, expand=True, bgcolor="#1e1e1e", border_radius=8, padding=10),
                ft.Row([self.start_button], alignment=ft.MainAxisAlignment.CENTER)
            ],
            expand=True
        )

    def did_mount(self):
        self.page = self.page  # Asegurarse de que self.page esté inicializado correctamente

    def start_sniffing_clicked(self, e):
        if not self.sniffing:
            self.sniffing = True
            self.stop_sniffing_event.clear()
            self.sniff_thread = Thread(target=self.sniff_packets)
            self.sniff_thread.start()
            log_intrusion("Iniciando captura de paquetes...", text_area=self.log_area)
            self.start_button.text = "Detener"
        else:
            self.sniffing = False
            self.stop_sniffing_event.set()
            log_intrusion("Deteniendo captura de paquetes.", text_area=self.log_area)
            self.start_button.text = "Iniciar"
        if self.page:  # Verificar si self.page no es None
            self.page.update()

    def sniff_packets(self):
        try:
            scapy.sniff(prn=lambda packet: self.process_packet(packet), store=False, stop_filter=self.should_stop_sniffing)
        except Exception as e:
            log_intrusion(f"Error al capturar paquetes: {e}", text_area=self.log_area)

    def should_stop_sniffing(self, packet):
        return self.stop_sniffing_event.is_set()

    def process_packet(self, packet):
        analyze_packet(packet, self.log_area, gui=self)
        self.packet_count += 1
        self.packet_count_label.value = f"Paquetes Capturados: {self.packet_count}"
        if self.packet_count_label:  # Verificar si self.packet_count_label no es None
            self.packet_count_label.update()
