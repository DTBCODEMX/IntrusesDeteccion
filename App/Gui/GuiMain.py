# Creado por DTBCODE / 2024

import flet as ft
from .LoginGui import LoginWindow
from .DetectionGui import DetectionWindow

# Función para iniciar la aplicación de login
def start_login_app():
    def start(page):
        page.title = "Sistema de Detección de Intrusiones - Login"
        page.horizontal_alignment = "center"
        page.vertical_alignment = "center"
        page.bgcolor = "black"

        def switch_to_detection():
            page.window_destroy()
            p = ft.Process(target=start_detection_app)
            p.start()

        login_window = LoginWindow(switch_to_detection)
        page.add(login_window.build())

    ft.app(target=start)

# Función para iniciar la aplicación de detección
def start_detection_app():
    def start(page):
        page.title = "Sistema de Detección de Intrusiones"
        page.horizontal_alignment = "center"
        page.vertical_alignment = "center"
        page.bgcolor = "black"

        detection_window = DetectionWindow()
        page.add(detection_window.build())

    ft.app(target=start)
