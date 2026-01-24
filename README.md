# Honeypot-Python-Lab
Honeypot modular en Python (POO) para detección de intrusos y análisis de firmas de ataque
# ⚙️ Configuracion del Honeypot
CAMBIA ESTA IP POR LA ACTUAL NO necesita ser de la misma marca de laptop DELL

* Ejemplo dentro de cliente.py

ip_servidor = "192.168.100.8" # <-- Sustituye por tu IPv4 actual

dentro del archivo cliente.py cambias la ip por la que tienes comprobandola actual con cmd usando el comando ipconfig ubicas solo la IPv4 cambiala por tu ip en el archivo cliente.py
# 🛡️ Python Honeypot & Intrusion Detection System (POO)

Este proyecto es un Honeypot de baja interacción diseñado para detectar y clasificar intentos de intrusión en tiempo real. 

## 🚀 Características
- **Programación Orientada a Objetos (POO):** Código modular y escalable.
- **Clasificación de Payloads:** Identifica SQL Injection, XSS, Path Traversal y Web Shells mediante firmas.
- **Persistencia en SQLite:** Registro detallado de eventos para análisis forense digital.
- **Resiliencia:** Manejo de errores y límites de conexión por IP para evitar DoS en el propio sensor.

## 🛠️ Entorno de Pruebas
- **Hardware:** Laptop Dell / Samsung A207 (vía Hotspot).
- **Software:** Python 3.12, Thonny, Pydroid 3.

## 📊 Firmas de Detección (Lógica Bit a Bit y Strings)
El sistema utiliza comparaciones de patrones para detectar:
- `OR 1=1` -> SQL Injection
- `<SCRIPT>` -> Cross-Site Scripting
- `../` -> Path Traversalnfiguracion
