# Honeypot-Python-Lab
Honeypot modular en Python (POO) para detección de intrusos y análisis de firmas de ataque

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

# 🚦 Manejo de hilos (threading)
- **Pensado en la eficiencia** y evitar perdida de datos en registro de conexiones
- **Optimizado para dispositivos de poca capacidad**
