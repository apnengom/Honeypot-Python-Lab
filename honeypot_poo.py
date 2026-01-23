import socket
import sqlite3
from datetime import datetime

class GestorDB:
    def __init__(self, nombre_db="auditoria_seguridad.db"):
        self.nombre_db = nombre_db
        self._inicializar_tablas()

    def _conectar(self):
        return sqlite3.connect(self.nombre_db)

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
        if not datos_up: return "PORT SCAN"
        
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
        with self._conectar() as conn:
            conn.execute(
                "INSERT INTO eventos_red (fecha_hora, ip_origen, puerto_destino, categoria, datos_recibidos) VALUES (?, ?, ?, ?, ?)",
                (fecha, ip, puerto, categoria, datos)
            )

    def obtener_total_conexiones(self, ip):
        """Sinceridad: Sin esto, tu Honeypot es vulnerable a DoS"""
        with self._conectar() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM eventos_red WHERE ip_origen = ?", (ip,))
            return cursor.fetchone()[0]

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

class Honeypot:
    def __init__(self, ip="0.0.0.0", puerto=8888, max_por_ip=3):
        self.ip = ip
        self.puerto = puerto
        self.max_por_ip = max_por_ip # Límite de seguridad
        self.db = GestorDB()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def iniciar(self):
        try:
            self.sock.bind((self.ip, self.puerto))
            self.sock.listen(5)
            print(f"🛡️ Honeypot activo en puerto {self.puerto} (Límite: {self.max_por_ip} conn/IP)")
            
            while True:
                cliente, direccion = self.sock.accept()
                ip_atacante = direccion[0]
                
                # --- VERIFICACIÓN DE LÍMITE ---
                if self.db.obtener_total_conexiones(ip_atacante) >= self.max_por_ip:
                    print(f"🚫 IP BLOQUEADA (Exceso de intentos): {ip_atacante}")
                    cliente.close()
                    continue

                self._manejar_conexion(cliente, direccion)
        except KeyboardInterrupt:
            print("\n🛑 Apagado manual.")
        finally:
            self.sock.close()

    def _manejar_conexion(self, cliente, direccion):
        try:
            datos = cliente.recv(1024).decode('utf-8', errors='ignore')
            # Usamos el puerto del atacante (direccion[1]) para mayor detalle
            self.db.registrar_evento(direccion[0], direccion[1], datos)
            self.db.mostrar_eventos()
        finally:
            cliente.close()

if __name__ == "__main__":
    trampa = Honeypot(puerto=8888, max_por_ip=5)
    trampa.iniciar()