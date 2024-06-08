# Creado por DTBCODE / 2024

import flet as ft
from auth import log_user_info
from config import USERNAME, PASSWORD

# Clase para la ventana de login
class LoginWindow(ft.UserControl):
    def __init__(self, switch_to_detection):
        super().__init__()
        self.switch_to_detection = switch_to_detection

    # Construcción de la GUI del login
    def build(self):
        self.username_input = ft.TextField(
            label="Correo electrónico",
            border_radius=8,
            color="white",
            bgcolor="transparent",
            border_color="white",
            border_width=2,
            text_style=ft.TextStyle(color="white")
        )
        self.password_input = ft.TextField(
            label="Contraseña",
            password=True,
            can_reveal_password=True,
            border_radius=8,
            color="white",
            bgcolor="transparent",
            border_color="white",
            border_width=2,
            text_style=ft.TextStyle(color="white")
        )
        self.remember_me = ft.Checkbox(label="Recordar contraseña")
        self.login_button = ft.ElevatedButton(
            text="INICIAR",
            on_click=self.check_credentials,
            bgcolor="white",
            color="black",
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                animation_duration=300,
                padding=ft.Padding(15, 15, 15, 15)
            )
        )
        self.social_buttons = ft.Row(
            [
                ft.IconButton(icon=ft.icons.EMAIL, icon_color="white"),
                ft.IconButton(icon=ft.icons.FACEBOOK, icon_color="white"),
                ft.IconButton(icon=ft.icons.APPLE, icon_color="white"),
            ],
            alignment=ft.MainAxisAlignment.CENTER
        )
        self.create_account_text = ft.Row(
            [
                ft.Text("¿No tiene una cuenta?", color="white"),
                ft.Text("Crear cuenta", color="white", weight=ft.FontWeight.BOLD)
            ],
            alignment=ft.MainAxisAlignment.CENTER
        )

        return ft.Container(
            content=ft.Column(
                [
                    ft.Text("Iniciar Sesión", size=30, color="white", weight=ft.FontWeight.BOLD),
                    self.username_input,
                    self.password_input,
                    self.remember_me,
                    ft.Container(
                        content=self.login_button,
                        alignment=ft.alignment.center,
                        padding=ft.Padding(0, 20, 0, 20)
                    ),
                    ft.Text("Iniciar sesión con", color="white"),
                    self.social_buttons,
                    self.create_account_text,
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10
            ),
            alignment=ft.alignment.center,
            padding=20,
            border_radius=ft.border_radius.all(20),
            gradient=ft.LinearGradient(
                begin=ft.alignment.top_center,
                end=ft.alignment.bottom_center,
                colors=["#4d1d4d", "#2b2aea"]
            ),
            width=300,
            height=500,
        )

    # Verificación de credenciales del usuario
    def check_credentials(self, e):
        if self.username_input.value == USERNAME and self.password_input.value == PASSWORD:
            log_user_info(None, self.username_input.value)
            self.switch_to_detection()
        else:
            self.page.snack_bar = ft.SnackBar(ft.Text("Invalid username or password", color="red"))
            self.page.snack_bar.open = True
            if self.page:
                self.page.update()
