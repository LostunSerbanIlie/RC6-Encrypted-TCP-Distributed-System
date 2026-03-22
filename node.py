import socket

# Conecteaza-te la Master (IP-ul de pe Host-Only al Win 11)
MASTER_IP = '192.168.56.1' 
PORT = 8000

print(f"[NOD] Incerc sa ma conectez la Master pe {MASTER_IP}:{PORT}...")

try:
    # Creare socket TCP si conectare
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((MASTER_IP, PORT))
    
    print("[NOD] Conectat cu succes la Master!")
    
    # Trimitem mesajul HELLO_MASTER
    mesaj = "HELLO_MASTER! Sunt un nod gata de actiune."
    client_socket.sendall(mesaj.encode('utf-8'))
    
    # Asteptam raspunsul (cheia) de la Master
    raspuns_master = client_socket.recv(1024).decode('utf-8')
    print(f"[NOD] Master-ul mi-a raspuns: {raspuns_master}")
    
    client_socket.close()

except ConnectionRefusedError:
    print("[EROARE] Conexiunea refuzata! Masterul e pornit? (Sau Firewall pe Win 11 blocheaza portul 8000)")
except Exception as e:
    print(f"[EROARE] A aparut o problema: {e}")