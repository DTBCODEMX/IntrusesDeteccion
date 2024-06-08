import flet as ft
from multiprocessing import Process
from gui import LoginWindow, DetectionWindow

def start_login_app():
    def start(page: ft.Page):
        page.title = "Sistema de Detección de Intrusiones - Login"
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.bgcolor = ft.colors.BLACK

        def switch_to_detection():
            page.window_destroy()  # Destruir la ventana de login
            p = Process(target=start_detection_app)
            p.start()

        login_window = LoginWindow(switch_to_detection)
        page.add(login_window.build())

    ft.app(target=start)

def start_detection_app():
    def start(page: ft.Page):
        page.title = "Sistema de Detección de Intrusiones"
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.bgcolor = ft.colors.BLACK

        detection_window = DetectionWindow()
        page.add(detection_window.build())

    ft.app(target=start)

if __name__ == "__main__":
    start_login_app()
