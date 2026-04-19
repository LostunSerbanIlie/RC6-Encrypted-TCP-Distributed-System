import socket
import custom_rsa


class PeerNode:
    def __init__(self, master_host='192.168.56.1', master_port=8000):
        self.master_host = master_host
        self.master_port = master_port

        # stores the DEK when received
        self.network_dek = None

        # generating the RSA key pair
        # it returnes 2 tuples ((e, N), (d, N))
        print("[*] Generating local RSA-1024 key pair...")
        self.public_key, self.private_key = custom_rsa.generate_keypair(1024)

    def get_serialized_public_key(self):
        """
        Converts our custom Public Key (e, N) into a string format
        encoded as bytes, so it can be sent over the TCP socket.
        """
        e, N = self.public_key
        # makes an "e,N" string and transforms it into bytes
        return f"{e},{N}".encode('utf-8')

    def connect_to_master(self):
        """
        Connects to the Master, sends the Public Key, and receives the encrypted DEK.
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f"[*] Connecting to Master at {self.master_host}:{self.master_port}...")
        client_socket.connect((self.master_host, self.master_port))

        # sends the public key to the master
        pub_key_bytes = self.get_serialized_public_key()
        print("[*] Sending Public Key to Master...")
        client_socket.sendall(pub_key_bytes)

        # receives the Encrypted DEK
        # reading up to 4096 bytes to ensure the whole RSA ciphertext is received
        encrypted_dek = client_socket.recv(4096)
        print(f"[*] Received encrypted payload from Master ({len(encrypted_dek)} bytes).")

        # decrypt the payload using our Private Key an custom math
        print("[*] Decrypting network DEK using local Private Key...")
        # calls the method that does M = C^d mod N
        self.network_dek = custom_rsa.decrypt(self.private_key, encrypted_dek)

        print(f"\n[SUCCESS] DEK successfully recovered!")
        print(f" -> Recovered DEK (hex): {self.network_dek.hex(' ')}")
        
        client_socket.close()

if __name__ == "__main__":
    node = PeerNode()
    node.connect_to_master()