import os
import socket
import threading
import time
import custom_rsa
from RC6.RC6_CBC import RC6_CBC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import tkinter as tk
from tkinter import filedialog

class MasterNode:
    """
    The central Master Node responsible for generating the DEK,
    listening for nodes, distributing the key, and participating as a P2P node.
    """

    def __init__(self, host='192.168.56.1', port=8000, p2p_port=9000):
        self.host = host
        self.port = port
        self.p2p_port = p2p_port
        
        self.peers = set() # Using a set for unique IPs
        self.dek = None
        self.rc6_engine = None
        self.shutdown_flag = threading.Event()

        # List of active peers for menu logic
        self.lista_peers = []

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

    # =====================================================================
    # 1st Role: TRACKER (Administrates keys and nodes on port 8000)
    # =====================================================================
    def broadcast_peer_list(self):
        """Sends the IP list to all the nodes and deletes the dead ones."""
        peer_list_str = ",".join(self.peers)
        header = f"UPDATE_PEERS|{peer_list_str}".ljust(256, '\x00').encode('utf-8')
        
        dead_peers = set()
        
        for peer_ip in self.peers:
            if peer_ip == self.host: 
                continue # we don't send the list to ourselves
                
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((peer_ip, 9000)) # Sending on their P2P port
                s.sendall(header)
                s.close()
            except Exception:
                # keep-alive system: if the node doesn't respond, we mark it for deletion
                print(f"[TRACKER] Node {peer_ip} is not responding. Removing it from the network!")
                dead_peers.add(peer_ip)

        # if there are dead nodes, we delete them and broadcast the updated list again
        if dead_peers:
            self.peers -= dead_peers
            self.broadcast_peer_list()

    def tracker_server(self):
        """Runs in the background and waits for new nodes to connect."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        print(f"[TRACKER] Listening for new connections on {self.host}:{self.port}...")

        while not self.shutdown_flag.is_set():
            server_socket.settimeout(1.0)
            try:
                client_socket, client_address = server_socket.accept()
            except socket.timeout:
                continue

            node_ip = client_address[0]
            print(f"\n[TRACKER] New node connected from: {node_ip}")

            try:
                pub_key_str = client_socket.recv(4096).decode('utf-8')
                e_str, N_str = pub_key_str.split(',')
                node_public_key = (int(e_str), int(N_str))

                print(f"[TRACKER] Encrypting DEK for {node_ip}...")
                encrypted_dek = custom_rsa.encrypt(node_public_key, self.dek)
                client_socket.sendall(encrypted_dek)
                
                # add it to the routing table and broadcast updates
                self.peers.add(node_ip)
                print(f"[TRACKER] Routing table updated. Broadcasting...")
                self.broadcast_peer_list()
                
            except Exception as e:
                print(f"[TRACKER] Error handling node {node_ip}: {e}")
            finally:
                client_socket.close()
        
        server_socket.close()
        print("[TRACKER] Tracker server shut down cleanly.")

    # =====================================================================
    # 2nd Role: NORMAL P2P NODE (Sends/receives files on port 9000)
    # =====================================================================
    def p2p_listener(self):
        """Listens for incoming files or P2P update messages."""
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
                header = client_socket.recv(256).decode('utf-8').strip('\x00')
                
                # keep-alive mechanism
                if not header or header == "PING":
                    client_socket.close()
                    continue

                # receives special UPDATE_PEERS packet (redundant for Master, but kept for safety)
                if header.startswith("UPDATE_PEERS|"):
                    client_socket.close()
                    continue

                # a normal file transfer
                filename, filesize_str = header.split('|')
                filesize = int(filesize_str)
                print(f"\n[MASTER-P2P] Receiving file: {filename} ({filesize} bytes)")

                # recompile the chunks
                received_data = b""
                bytes_received = 0
                
                while bytes_received < filesize:
                    chunk = client_socket.recv(1024)
                    if not chunk: break
                    received_data += chunk
                    bytes_received += len(chunk)
                    
                    # updating progress for every MB
                    if bytes_received % (1024 * 1024) == 0 or bytes_received == filesize:
                        mb_recv = bytes_received / (1024 * 1024)
                        total_mb = filesize / (1024 * 1024)
                        print(f"  -> Downloaded: {mb_recv:.1f} MB / {total_mb:.2f} MB", end='\r')
                
                print("\n[*] All chunks received. Decrypting with RC6 (This might take a while for large files)...")
                
                decrypted_data = self.rc6_engine.decrypt(received_data)
                
                # logic for file or message reception
                if filename == "DIRECT_MSG":
                    message = decrypted_data.decode('utf-8')
                    print(f"\n[DECRYPTED direct message received from {addr[0]}]: {message}\n")
                else:
                    save_path = f"master_received_{filename}"
                    with open(save_path, "wb") as f:
                        f.write(decrypted_data)
                    print(f"[MASTER-P2P] File saved as: {save_path}\n")
                
            except Exception as e:
                print(f"[MASTER-P2P] Reception error: {e}")
            finally:
                client_socket.close()
                
        server_socket.close()
        print("[MASTER-P2P] P2P Listener shut down cleanly.")

    def send_file_p2p(self, target_ip, filepath):
        """Encrypts and sends a file to a specific peer."""
        if not os.path.exists(filepath):
            return print("[ERROR] File does not exist!")

        with open(filepath, "rb") as f:
            plaintext = f.read()

        ciphertext = self.rc6_engine.encrypt(plaintext)
        filename = os.path.basename(filepath)
        filesize = len(ciphertext)
        header = f"{filename}|{filesize}".ljust(256, '\x00').encode('utf-8')

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, 9000))
            s.sendall(header)
            
            # CHUNKING: send the encrypted data in blocks of 1024 bytes
            bytes_sent = 0
            for i in range(0, filesize, 1024):
                chunk = ciphertext[i : i + 1024]
                s.sendall(chunk)
                bytes_sent += len(chunk)
                
                # shows progress for every MB sent
                if bytes_sent % (1024 * 1024) == 0 or bytes_sent == filesize:
                    mb_sent = bytes_sent / (1024 * 1024)
                    total_mb = filesize / (1024 * 1024)
                    print(f"  -> Uploaded: {mb_sent:.1f} MB / {total_mb:.2f} MB", end='\r')
                    
            print(f"\n[SUCCESS] File sent successfully to {target_ip}!")

            s.close()
        except Exception as e:
            print(f"[ERROR] Failed connection to {target_ip}: {e}")

    def send_direct_msg(self, target_ip, text_msg):
        """Encrypts and sends a direct message from RAM to a known node"""
        ciphertext = self.rc6_engine.encrypt(text_msg.encode('utf-8'))
        msg_len = len(ciphertext)

        # adding the DIRECT_MSG header so the listener knows how to handle it
        header = f"DIRECT_MSG|{msg_len}".ljust(256, '\x00').encode('utf-8')

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, 9000))
            s.sendall(header)

            # chunking the message in 1024 bytes pieces
            for i in range(0, msg_len, 1024):
                s.sendall(ciphertext[i : i + 1024])
                
            print("[SUCCESS] Direct message sent!")
            s.close()

        except Exception as e:
            print(f"\n[ERROR] Cannot send to {target_ip} (Error: {e})")
            # auto-clenup logic for the agenda
            if target_ip in self.peers:
                self.peers.remove(target_ip)
                print("[AUTO-CLEANUP] Deleted the node from table.")    

    def menu(self):
        """Interactive terminal menu replacing the separate shutdown_listener."""
        while not self.shutdown_flag.is_set():
            time.sleep(0.5) # delay to keep the console clean
            print("\nMASTER P2P MENU")
            print("1. Send text message (from the console)")
            print("2. Send a file (local, on this PC)")
            print("3. Refresh peers")
            print("4 or 'quit' (Shuts down network)")
            
            # Always ensure self.peers is a set
            if isinstance(self.peers, list):
                self.peers = set(self.peers)

            lista_peers = list(self.peers - {self.host})
            if not lista_peers:
                print("(0 nodes connected yet)")
            else:
                print("Available nodes:")
                for idx, ip in enumerate(lista_peers):
                    print(f"  [{idx}] {ip}")

            # this input accepts '1', '2', or 'quit'
            choice = input("Choose option (or type 'quit'): ").strip().lower()
            
            if not choice:
                continue

            if choice == '1':
                if not lista_peers:
                    print("[!] No nodes available to send to!")
                    continue
                    
                target_idx = input("Choose node number ([0], [1], ...): ")
                try:
                    target_ip = lista_peers[int(target_idx)]
                    msg = input("Write message: ")
                    self.send_direct_msg(target_ip, msg) # calling the send method
                except (ValueError, IndexError):
                    print("[!] Invalid selection.")

            elif choice == '2':
                if not lista_peers:
                    print("[!] Table is empty!")
                    continue
                target_idx = input(f"Choose ID (0 - {len(lista_peers)-1}): ")
                try:
                    target_ip = lista_peers[int(target_idx)]
                    
                    # GUI file picker
                    print("[*] Selection window is opening...")
                    root = tk.Tk()
                    root.withdraw() # hide the main empty window
                    root.attributes('-topmost', True) # bring to front
                    
                    filepath = filedialog.askopenfilename(title="Choose a file to send")
                    
                    if filepath:
                        # displaying the file size
                        file_size_kb = os.path.getsize(filepath) / 1024
                        print(f"[*] Selected: {filepath} ({file_size_kb:.2f} KB)")
                    else:
                        print("[-] Selection canceled.")
                except (ValueError, IndexError):
                    print("[!] ID invalid.")

            elif choice == '3':
                print("\n[*] Broadcasting PING...")
                active_peers = set()
                offline_peers = set()

                for ip in self.peers:
                    if ip == self.host:
                        continue  # don't ping self
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1.0) # waiting 1 s 
                        s.connect((ip, self.p2p_port))
                        # sending a 256 bytes to respect the header structure
                        s.sendall("PING".ljust(256, '\x00').encode('utf-8'))
                        s.close()
                        active_peers.add(ip)
                        print(f"  [+] {ip} is ONLINE")
                    except Exception:
                        print(f"  [-] {ip} gave no response. Eliminated!")
                        offline_peers.add(ip)

                # remove offline peers from self.peers
                self.peers -= offline_peers

                print("[*] Refresh completed.")
                continue

            elif choice == 'quit' or choice == '3':
                print("\n[MASTER] Exit command received. Shutting down gracefully...")
                self.shutdown_flag.set()
                break
            else:
                print("[!] Invalid option. Please try again.")

    def start(self):
        """
        Initializes the crypto engine, derives the DEK, and starts both roles (Threads).
        """
        print("[*] Initializing Master Node...")
        password = input("Enter the Master Password to generate the DEK: ")
        print("[*] Generating secure DEK...")
        self.derive_dek(password)
        print(f"[SUCCESS] DEK generated (hex): {self.dek.hex()}")
        print("-" * 50)
        
        # arm the RC6 Engine
        self.rc6_engine = RC6_CBC(self.dek)
        
        # master adds itself to the routing table
        self.peers.add(self.host) 
        
        # start 1st role (Tracker) in the background
        t1 = threading.Thread(target=self.tracker_server, daemon=True)
        t1.start()
        
        # start 2nd role (P2P Listener) in the background
        t2 = threading.Thread(target=self.p2p_listener, daemon=True)
        t2.start()
        
        # launch the interactive menu on the main thread
        try:
            self.menu()            
        except KeyboardInterrupt:
            # catch CTRL+C just in case
            print("\n[MASTER] Force quit detected. Shutting down...")
            self.shutdown_flag.set()

if __name__ == "__main__":
    master = MasterNode(host='192.168.56.1', port=8000)
    master.start()