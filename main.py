import socket
import threading
from db.base_datos import GestorDB

class Honeypot:
    def __init__(self, ip, puerto=8888, max_por_ip=5):
        self.ip = ip
        self.puerto = puerto
        self.max_por_ip = max_por_ip
        self.db = GestorDB()

    def iniciar(self):
        # Usar with para asegurar que el socket se cierre bien al fallar
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self.ip, self.puerto))
                sock.listen(100)
                print(f"🛡️ Honeypot activo en {self.ip}:{self.puerto} (Máx: {self.max_por_ip} conn/IP)")
                
                while True:
                    cliente, direccion = sock.accept()
                    # Pasamos el cliente al hilo
                    hilo = threading.Thread(target=self._procesar_cliente, args=(cliente, direccion))
                    hilo.daemon = True
                    hilo.start()
                
            except Exception as e:
                print(f"❌ Error crítico: {e}")

    def _procesar_cliente(self, cliente, direccion):
        ip_atacante = direccion[0]
        puerto_atacante = direccion[1]
        try:
            # 1. Verificar límite (SQLite es rápido)
            if self.db.obtener_total_conexiones(ip_atacante) >= self.max_por_ip:
                # Opcional: enviar mensaje de rechazo antes de cerrar
                return

            # 2. Recibir datos
            cliente.settimeout(100.0) 
            datos = cliente.recv(1024).decode('utf-8', errors='ignore')
            
            if datos:
                self.db.registrar_evento(ip_atacante, puerto_atacante, datos)
            
        except ConnectionResetError:
            print(f"⚠️ Conexión reseteada por {ip_atacante}")
        except Exception as e:
            print(f"⚠️ Error procesando {ip_atacante}: {e}")
        finally:
            cliente.close() # Cerramos siempre al final

if __name__ == "__main__":
    # IMPORTANTE: 127.0.0.1 para pruebas locales en CMD
    # Dentro del if __name__ == "__main__": de tu Honeypot
    trampa = Honeypot(ip="0.0.0.0", puerto=8888, max_por_ip=10)
    trampa.iniciar()
