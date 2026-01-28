import socket

ip_local = "127.0.0.1" 
puerto = 8888 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    try:
        print("✅ Conectado al Honeypot")
        consulta = input("Ingresa su consulta: ")
        client.connect((ip_local, puerto))
        client.sendall(consulta.encode())
        
        # Opcional: Solo si el servidor envía respuesta (ver abajo)
        # respuesta = client.recv(1024)
        # print(f"Respuesta: {respuesta.decode()}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
