import os
import socket
import threading
import custom_rsa
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
            
                # receive the Custom Public key from the Node (string format "e,N")
                pub_key_str = client_socket.recv(4096).decode('utf-8')
                print("[MASTER] Received Custom Public Key from Node")

                # load the numbers into a tuple of Integers
                e_str, N_str = pub_key_str.split(',')
                node_public_key = (int(e_str), int(N_str))

                # encapsulation/inception - encrypting the DEK using our Custom RSA
                print("[MASTER] Encrypting DEK with the Node's Custom RSA Public Key...")
                encrypted_dek = custom_rsa.encrypt(node_public_key, self.dek)

                # send the encrypted payload back to the Node
                print(f"[MASTER] Sending encrypted DEK ({len(encrypted_dek)} bytes) over the network...")
                client_socket.sendall(encrypted_dek)

                # close connection for the current node
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