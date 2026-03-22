import socket

# Configurare cu noul IP Host-Only
HOST = '192.168.56.1'  # Asculta strict pe rețeaua VirtualBox
PORT = 8000            # Portul pentru Planul de Control

# Creare socket TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Permite refolosirea portului (evită eroarea "Address already in use")
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Pornim serverul
server_socket.bind((HOST, PORT))
server_socket.listen(5) # Asteapta pana la 5 conexiuni simultane

print(f"[MASTER] Server pornit. Astept conexiuni pe {HOST}:{PORT}...")

while True:
    # Asteapta sa se conecteze un Nod
    client_socket, client_address = server_socket.accept()
    print(f"[MASTER] Conexiune noua acceptata de la nodul: {client_address[0]}:{client_address[1]}")
    
    # Primeste mesajul HELLO de la nod (citim max 1024 bytes)
    date_primite = client_socket.recv(1024).decode('utf-8')
    print(f"[MASTER] Am primit mesajul: {date_primite}")
    
    # Trimite un raspuns inapoi (simulam trimiterea cheii DEK)
    raspuns = "WELCOME_KEY: Parola_Super_Secreta_RC6"
    client_socket.sendall(raspuns.encode('utf-8'))
    
    # Inchidem conexiunea cu acest nod
    client_socket.close()
    print("[MASTER] Conexiune închisă. Aștept următorul nod...\n")