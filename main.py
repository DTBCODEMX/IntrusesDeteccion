import tkinter as tk
from gui import IntrusionDetectionGUI
import ttkbootstrap as ttk

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = IntrusionDetectionGUI(root)
    # Agregar estilos para texto sospechoso
    app.text_area.tag_config('suspicious_port', foreground='orange')
    app.text_area.tag_config('failed_login', foreground='red')
    app.text_area.tag_config('port_scan', foreground='yellow')
    app.text_area.tag_config('syn_flood', foreground='purple')
    app.text_area.tag_config('ddos', foreground='blue')
    root.mainloop()
