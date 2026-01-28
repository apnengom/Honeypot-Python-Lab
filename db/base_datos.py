import json
import sqlite3
import threading
from datetime import datetime

class GestorDB:
    def __init__(self, nombre_db="auditoria_seguridad.db"):
        self.nombre_db = nombre_db
        self.lock = threading.Lock()
        self._inicializar_tablas()

    def _conectar(self):
        # check_same_thread=False permite que sqlite funcione con hilos
        return sqlite3.connect(self.nombre_db, check_same_thread=False)

    def _inicializar_tablas(self):
        with self._conectar() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS eventos_red (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha_hora TEXT NOT NULL,
                    ip_origen TEXT NOT NULL,
                    puerto_destino INTEGER,
                    categoria TEXT,
                    datos_recibidos TEXT
                )
            ''')

    def clasificar_payload(self, datos):
        datos_up = datos.upper()
        if not datos_up.strip(): return "PORT SCAN"
        firmas = {
            "SQL INJECTION": ["SELECT", "UNION", "DROP", "OR 1=1", "--"],
            "XSS": ["<SCRIPT>", "ALERT(", "ONERROR"],
            "PATH TRAVERSAL": ["../", "/ETC/PASSWD"],
            "WEB SHELL": ["CMD=", "SHELL", "BASH"],
            "HTTP SCAN": ["GET /", "POST /", "CONNECT"]
        }
        for cat, patrones in firmas.items():
            if any(p in datos_up for p in patrones): return cat
        return "NONE"

    def registrar_evento(self, ip, puerto, datos):
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        categoria = self.clasificar_payload(datos)
        
        # 1. Base de Datos
        try:
            with self._conectar() as conn:
                conn.execute(
                    "INSERT INTO eventos_red (fecha_hora, ip_origen, puerto_destino, categoria, datos_recibidos) VALUES (?, ?, ?, ?, ?)",
                    (fecha, ip, puerto, categoria, datos)
                )
            self.mostrar_eventos()
            
        except Exception as e:
            print(f"Error DB: {e}")

        # 2. JSON y Pantalla (Sección Crítica)
        with self.lock:
            info = {"Fecha": fecha, "IP": ip, "Port": puerto, "Cat": categoria, "Data": datos}
            with open("logs.jsonl", "a", encoding='utf-8') as f:
                f.write(json.dumps(info) + "\n")
            
    def obtener_total_conexiones(self, ip):
        """Consulta la base de datos para contar registros de una IP específica."""
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                # Contamos cuántas filas tienen esa IP_origen
                cursor.execute("SELECT COUNT(*) FROM eventos_red WHERE ip_origen = ?", (ip,))
                resultado = cursor.fetchone()
                return resultado[0] if resultado else 0
        except Exception as e:
            print(f"❌ Error al consultar límites: {e}")
            return 0

    def mostrar_eventos(self):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT fecha_hora, ip_origen, puerto_destino, categoria, datos_recibidos FROM eventos_red ORDER BY id DESC LIMIT 5')
                filas = cursor.fetchall()

                # Formato ajustado para pantallas Dell y móviles
                print(f"\n{'FECHA':<28} | {'IP ORIGEN':<16} | {'PORT':<5} | {'CATEGORIA':<14} | {'DATOS'}")
                print("-" * 80)
                
                for f in filas:
                    # f[0]=fecha, f[1]=ip, f[2]=puerto, f[3]=cat, f[4]=datos
                    peticion = str(f[4]).replace('\n', ' ')[:15]
                    print(f"{f[0]:<20} | {f[1]:<15} | {f[2]:<5} | {f[3]:<15} | {peticion}...")
        except sqlite3.Error as e:
            print(f"❌ Error DB: {e}")
