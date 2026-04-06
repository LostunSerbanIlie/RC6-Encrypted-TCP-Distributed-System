import os
import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class MasterNode:
    """
    The central Master Node responsible for generating the DEK,
    listening for nodes and distributing the key.
    """

    def __init__(self, host='192.168.56.1', port=8000):
        self.host = host
        self.port = port
        self.peers = {} # ARP-like
        self.dek = None
        self.salt = None # adds noise to the DEK

    def derive_dek(self, password: str):
        """
        Derives a perfect 16-byte DEK using Password-Based Key Derivation Function 2
        """
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 16,
            salt = self.salt,
            iterations = 100000,
        )
        self.dek = kdf.derive(password.encode('utf-8'))

    def start(self):
        """
        Initializes the crypto engine and starts the TCP listening server.
        """
        # cryptography setup
        password = input("Enter the Master Password to generate the DEK: ")
        print("[*] Generating secure DEK...")
        self.derive_dek(password)
        print(f"[SUCCESS] DEK generated (hex): {self.dek.hex()}")
        print("-" * 50)

        # network setup
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        print(f"[MASTER] Server running. Listening for connections on {self.host}:{self.port}...\n")

        # shutdown_flag
        shutdown_flag = threading.Event()

        def shutdown_listener():
            while not shutdown_flag.is_set():
                try:
                    cmd = input()
                except EOFError:
                    break
                if cmd.strip().lower() == "quit":
                    print("[MASTER] Exit command received.")
                    shutdown_flag.set()
        
        listener_thread = threading.Thread(target=shutdown_listener, daemon=True)
        listener_thread.start()

        try:
            while not shutdown_flag.is_set():
                server_socket.settimeout(1.0)
                try:
                    client_socket, client_address = server_socket.accept()
                except socket.timeout:
                    continue
            
                # accept an incoming connection from a Node
                print(f"[MASTER] New connection accepted from node: {client_address[0]}:{client_address[1]}")

                # receives the greeting
                data_received = client_socket.recv(1024).decode('utf_8')
                print(f"[MASTER] Received message: {data_received}")

                # send the securely generated DEK (sent as hex string for now)
                raspuns = f"WELCOME_DEK:{self.dek.hex()}"
                client_socket.sendall(raspuns.encode('utf-8'))

                # close connection for this node
                client_socket.close()
                print("[MASTER] Connection closed. Waiting for the next node...\n")

        except KeyboardInterrupt:
            # gracefull close on CTRL+C
            print("\n[MASTER] Shutting down server...")
            server_socket.close()
        finally:
            server_socket.close()
            print("[MASTER] Server socket closed.")

if __name__ == "__main__":
    master = MasterNode(host='192.168.56.1', port=8000)
    master.start()