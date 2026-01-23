import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# CAMBIA ESTA IP por la de tu Dell en el Hotspot
ip_dell = "192.168.100.8" 

try:
    client.connect((ip_dell, 8888))
    client.send("Hola desde el Samsung A207M!".encode())
    respuesta = client.recv(1024).decode()
    print(f"📡 Respuesta de la Dell: {respuesta}")
except Exception as e:
    print(f"❌ {e}")
finally:
    client.close()