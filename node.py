import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class PeerNode:
    def __init__(self, master_host='192.168.56.1', master_port=8000):
        self.master_host = master_host
        self.master_port = master_port

        # stores the DEK when received
        self.network_dek = None

        # generating the RSA key pair
        print("[*] Generating local RSA-2048 key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def get_serialized_public_key(self):
        """
        Converts the Public Key object into a bytes format (PEM) 
        so it can be sent over the TCP socket.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def connect_to_master(self):
        """
        Connects to the Master, sends the Public Key, and receives the encrypted DEK.
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f"[*] Connecting to Master at {self.master_host}:{self.master_port}...")
        client_socket.connect((self.master_host, self.master_port))

        # sends the public key to the master
        pub_key_bytes = self._get_serialized_public_key()
        print("[*] Sending Public Key to Master...")
        client_socket.sendall(pub_key_bytes)

        # receives the Encrypted DEK
        # reading up to 4096 bytes to ensure the whole RSA ciphertext is received
        encrypted_dek = client_socket.recv(4096)
        print(f"[*] Received encrypted payload from Master ({len(encrypted_dek)} bytes).")

        # decrypt the payload using our Private Key
        print("[*] Decrypting network DEK using local Private Key...")
        self.network_dek = self.private_key.decrypt(
            encrypted_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(f"\n[SUCCESS] DEK successfully recovered!")
        print(f" -> Recovered DEK (hex): {self.network_dek.hex(' ')}")
        
        client_socket.close()

if __name__ == "__main__":
    node = PeerNode()
    node.connect_to_master()