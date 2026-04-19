import os
import socket
import threading
import time
import custom_rsa
from RC6.RC6_CBC import RC6_CBC 

class PeerNode:
    def __init__(self, master_host='192.168.56.1', master_port=8000, p2p_port=9000):
        self.master_host = master_host
        self.master_port = master_port
        self.p2p_port = p2p_port
        
        self.network_dek = None
        self.rc6_engine = None
        self.known_peers = [] # Local routing table updated by the Master
        self.shutdown_flag = threading.Event()
        
        # auto-detect our own IP so we don't send files to ourselves
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            self.my_ip = s.getsockname()[0]
        except Exception:
            self.my_ip = '127.0.0.1'
        finally:
            s.close()

        print(f"[*] Generating local Custom RSA-1024 key pair for {self.my_ip}...")
        self.public_key, self.private_key = custom_rsa.generate_keypair(1024)

    def get_serialized_public_key(self):
        """
        Converts our custom Public Key (e, N) into a string format
        encoded as bytes, so it can be sent over the TCP socket.
        """
        e, N = self.public_key
        return f"{e},{N}".encode('utf-8')

    def connect_to_master(self):
        """
        Connects to the Master, sends the Public Key, and receives the encrypted DEK.
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print(f"[*] Connecting to Master at {self.master_host}:{self.master_port}...")
        try:
            client_socket.connect((self.master_host, self.master_port))

            pub_key_bytes = self.get_serialized_public_key()
            print("[*] Sending Public Key to Master...")
            client_socket.sendall(pub_key_bytes)

            encrypted_dek = client_socket.recv(4096)
            print(f"[*] Received encrypted payload from Master ({len(encrypted_dek)} bytes).")

            print("[*] Decrypting network DEK using local Private Key...")
            self.network_dek = custom_rsa.decrypt(self.private_key, encrypted_dek)

            print(f"[SUCCESS] DEK successfully recovered!")
            print(f" -> Recovered DEK (hex): {self.network_dek.hex(' ')}")
            
            # RC6 engine
            self.rc6_engine = RC6_CBC(self.network_dek)
            print("[*] RC6 Engine ready!")
            
        except Exception as e:
            print(f"[ERROR] Failed to get DEK from Master: {e}")
        finally:
            client_socket.close()

    # =====================================================================
    # P2P MODULE: Listening, Chunking, Recompiling, Decrypting
    # =====================================================================
    def p2p_listener(self):
        """Listens for incoming files OR routing table updates from Master."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.p2p_port))
        server_socket.listen(5)
        
        while not self.shutdown_flag.is_set():
            server_socket.settimeout(1.0)
            try:
                client_socket, addr = server_socket.accept()
            except socket.timeout:
                continue
                
            try:
                # read the Metadata header (256 bytes)
                header = client_socket.recv(256).decode('utf-8').strip('\x00')
                
                # check if it is an update from Master
                if header.startswith("UPDATE_PEERS|"):
                    _, peer_str = header.split('|')
                    if peer_str:
                        # save the list, exclude our own ip
                        self.known_peers = [ip for ip in peer_str.split(',') if ip != self.my_ip]
                        print(f"\n[ROUTING] Table updated by Master! Online peers: {len(self.known_peers)}")
                    else:
                        self.known_peers = []
                    client_socket.close()
                    continue 
                    
                #  normal P2P file transfer
                filename, filesize_str = header.split('|')
                filesize = int(filesize_str)
                print(f"\n[INCOMING] Receiving file: {filename} from {addr[0]} ({filesize} encrypted bytes)")

                # recompile the chunks
                received_data = b""
                while len(received_data) < filesize:
                    chunk = client_socket.recv(1024)
                    if not chunk: break
                    received_data += chunk
                
                print("[*] All chunks received. Decrypting with RC6...")
                # decrypt the full assembled payload
                decrypted_data = self.rc6_engine.decrypt(received_data)
                
                # save to disk
                save_path = f"node_received_{filename}"
                with open(save_path, "wb") as f:
                    f.write(decrypted_data)
                print(f"[SUCCESS] File decrypted and saved as: {save_path}\n")
                
            except Exception as e:
                print(f"[ERROR] P2P Reception failed: {e}")
            finally:
                client_socket.close()
                
        server_socket.close()

    def send_file_p2p(self, target_ip, filepath):
        """Encrypts a file and sends it in 1024-byte chunks to the target."""
        if not os.path.exists(filepath):
            return print("[ERROR] File does not exist!")

        with open(filepath, "rb") as f:
            plaintext = f.read()

        # encrypt the entire file
        ciphertext = self.rc6_engine.encrypt(plaintext)
        filename = os.path.basename(filepath)
        filesize = len(ciphertext)
        
        # create the 256-byte padded header
        header = f"{filename}|{filesize}".ljust(256, '\x00').encode('utf-8')

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, self.p2p_port))
            
            # send header
            s.sendall(header)
            
            # CHUNKING: send the encrypted data in blocks of 1024 bytes
            for i in range(0, filesize, 1024):
                s.sendall(ciphertext[i : i + 1024])
                
            print(f"[SUCCESS] File sent successfully to {target_ip}!")
            s.close()
        except Exception as e:
            print(f"[ERROR] Could not send data to {target_ip}: {e}")
            
            if target_ip in self.known_peers:
                self.known_peers.remove(target_ip)
                print(f"[AUTO-CLEANUP] {target_ip} is offline. Deleting it from the peers table.")

    def menu(self):
        """Interactive Terminal Menu"""
        # start the listener on a background thread
        t = threading.Thread(target=self.p2p_listener, daemon=True)
        t.start()
        time.sleep(1)

        while not self.shutdown_flag.is_set():
            print("\n")
            print(" NODE P2P MENU")
            print("1. Send text message")
            print("2. Refresh peers")
            print("3. Quit")
            
            if not self.known_peers:
                print("\n(No other peers online yet)")
            else:
                print("\nAvailable peers in the network:")
                for idx, ip in enumerate(self.known_peers):
                    print(f"  [{idx}] {ip}")

            choice = input("\nChoose option: ").strip().lower()

            if choice == '1':
                if not self.known_peers:
                    print("[!] Routing table is empty! Wait for others to connect.")
                    continue
                    
                target_idx = input("Choose peer ID ([0], [1]...): ")
                try:
                    target_ip = self.known_peers[int(target_idx)]
                    msg = input("Write your secret message: ")
                    
                    # create a temporary file to send
                    with open("node_msg.txt", "w") as f: 
                        f.write(msg)
                    self.send_file_p2p(target_ip, "node_msg.txt")
                except (ValueError, IndexError):
                    print("[!] Invalid ID.")
                    
            elif choice == '2':
                continue # loops back and re-prints the menu
                
            elif choice == '3' or choice == 'quit':
                print("Shutting down Node...")
                self.shutdown_flag.set()
                break
            else:
                print("[!] Invalid option.")

if __name__ == "__main__":
    node = PeerNode(p2p_port=9000)
    node.connect_to_master()
    
    # only launch the menu if we got the correct DEK
    if node.network_dek:
        node.menu()