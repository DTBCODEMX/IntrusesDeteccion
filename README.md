# Sistema de Detección de Intrusos

## Descripción

Este proyecto implementa un sistema de detección de intrusos (IDS) utilizando Python. La aplicación está diseñada para monitorizar el tráfico de red y detectar actividades sospechosas, tales como acceso a puertos sospechosos, intentos fallidos de inicio de sesión, escaneos de puertos, ataques SYN flood y ataques DDoS.

## Estructura del Proyecto
/App
├── Gui/
│ ├── LoginGui.py
│ ├── DetectionGui.py
│ └── GuiMain.py
├── auth.py
├── config.py
├── detection.py
├── main.py


### Archivos y Directorios

- **Gui/LoginGui.py:** Contiene la implementación de la interfaz de usuario para el inicio de sesión.
- **Gui/DetectionGui.py:** Contiene la implementación de la interfaz de usuario para la detección de intrusos.
- **Gui/GuiMain.py:** Integra las dos interfaces GUI, permitiendo la navegación entre ellas.
- **auth.py:** Maneja la autenticación de usuarios, registrando la información en una base de datos SQLite.
- **config.py:** Configuración del sistema, incluyendo parámetros de detección y configuración de logs.
- **detection.py:** Implementa la lógica de detección de intrusos, incluyendo la máquina de estados para manejar las transiciones entre estados.
- **main.py:** Punto de entrada principal de la aplicación, inicia la interfaz de inicio de sesión.

## Uso de la Aplicación

1. **Iniciar la Aplicación:**
   - Ejecuta el archivo `main.py` para iniciar la aplicación de detección de intrusos.

2. **Autenticación de Usuario:**
   - La interfaz de inicio de sesión permite a los usuarios autenticarse. Las credenciales por defecto se configuran en el archivo `config.py`.

3. **Monitorización de la Red:**
   - Una vez autenticado, el usuario puede acceder a la interfaz de detección de intrusos, donde puede iniciar y detener la captura de paquetes de red.
   - La aplicación analiza los paquetes en tiempo real y registra actividades sospechosas en los logs.

4. **Visualización de Logs:**
   - Los eventos detectados se muestran tanto en la interfaz gráfica como en la terminal, proporcionando visibilidad completa sobre las transiciones de estado y otros eventos importantes.

## Propósito

Este sistema de detección de intrusos está diseñado para ser utilizado en entornos de red donde se requiere una monitorización continua del tráfico para identificar y responder a posibles amenazas de seguridad. La aplicación es adecuada para redes pequeñas y medianas, proporcionando una capa adicional de seguridad al detectar actividades sospechosas y potencialmente maliciosas.

## Creador

Este proyecto fue creado por **DTBCODE: Damian Torres**, Ingeniero en ciberseguridad mexicano. Damian se especializa en el diseño e implementación de soluciones de seguridad informática para proteger redes y sistemas contra amenazas emergentes.

---
### Aplicaciones Necesarias

- **Python 3.8+**: Asegúrate de tener Python instalado. Puedes descargarlo desde [python.org](https://www.python.org/downloads/).

### Dependencias de Python

Para instalar las dependencias necesarias, ejecuta el siguiente comando:
```bash
pip install -r requirements.txt 
```


---

**Contacto:**

- **Email:** damiant1102@outlook.es
- **LinkedIn:** [linkedin.com/in/damiantorresmx](https://www.linkedin.com/in/damiantorresmx)

---

**Nota:**
Asegúrate de configurar adecuadamente las variables de entorno para las credenciales de usuario antes de ejecutar la aplicación. Puedes hacerlo estableciendo las variables `APP_USERNAME` y `APP_PASSWORD` en tu entorno.

---

¡Gracias por usar el Sistema de Detección de Intrusos!
