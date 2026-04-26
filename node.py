import os
import socket
import threading
import time
import custom_rsa
from RC6.RC6_CBC import RC6_CBC 

import tkinter as tk
from tkinter import filedialog

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
            # finding the IP based on the master connection
            s.connect((self.master_host, self.master_port))
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
                
                # ignores pings and empty connections
                if not header or header == "PING":
                    client_socket.close()
                    continue

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
                    
                # normal P2P file transfer
                filename, filesize_str = header.split('|')
                filesize = int(filesize_str)
                print(f"\n[INCOMING] Receiving file: {filename} from {addr[0]} ({filesize} encrypted bytes)")

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
                
                # decrypt the full assembled payload
                decrypted_data = self.rc6_engine.decrypt(received_data)
                
                # logic for file or message reception
                if filename == "DIRECT_MSG":
                    message = decrypted_data.decode('utf-8')
                    print(f"\n[DECRYPTED direct message received from {addr[0]}]: {message}\n")
                else:
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
                
            print(f"[SUCCESS] File sent successfully to {target_ip}!")
            s.close()
        except Exception as e:
            print(f"[ERROR] Could not send data to {target_ip}: {e}")
            
            if target_ip in self.known_peers:
                self.known_peers.remove(target_ip)
                print(f"[AUTO-CLEANUP] {target_ip} is offline. Deleting it from the peers table.")

    def send_direct_msg(self, target_ip, text_msg):
        """Encrypts and sends a direct message from RAM to a known node"""
        ciphertext = self.rc6_engine.encrypt(text_msg.encode('utf-8'))
        msg_len = len(ciphertext)

        # adding the DIRECT_MSG header so the listener knows how to handle it
        header = f"DIRECT_MSG|{msg_len}".ljust(256, '\x00').encode('utf-8')

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, self.p2p_port))
            s.sendall(header)

            # chunking the message in 1024 bytes pieces
            for i in range(0, msg_len, 1024):
                s.sendall(ciphertext[i : i + 1024])
                
            print("[SUCCESS] Direct message sent!")
            s.close()

        except Exception as e:
            print(f"\n[ERROR] Cannot send to {target_ip} (Error: {e})")
            # auto-cleanup logic for the agenda
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
            print("2. Send file (local file)")
            print("3. Refresh peers")
            print("4 or 'quit'")
            
            if not self.known_peers:
                print("\n(No other peers online yet)")
            else:
                print("\nAvailable peers in the network:")
                for idx, ip in enumerate(self.known_peers):
                    print(f"  [{idx}] {ip}")

            choice = input("\nChoose option: ").strip().lower()
            
            if not choice:
                continue

            if choice == '1':
                if not self.known_peers:
                    print("[!] Routing table is empty! Wait for others to connect.")
                    continue
                    
                target_idx = input("Choose peer ID ([0], [1]...): ")
                try:
                    target_ip = self.known_peers[int(target_idx)]
                    msg = input("Write your secret message: ")
                    
                    self.send_direct_msg(target_ip, msg) # calling the send method
                except (ValueError, IndexError):
                    print("[!] Invalid ID.")
                    
            elif choice == '2':
                if not self.known_peers:
                    print("[!] Routing table is empty! Wait for others to connect.")
                    continue
                    
                target_idx = input("Choose peer ID ([0], [1]...): ")
                try:
                    target_ip = self.known_peers[int(target_idx)]
                    
                    # GUI file picker
                    print("[*] Opening file selection dialog...")
                    root = tk.Tk()
                    root.withdraw() # Hide the main empty window
                    root.attributes('-topmost', True) # Bring to front
                    
                    filepath = filedialog.askopenfilename(title="Choose a file to send")
                    
                    if filepath:
                        # displaying the file size
                        file_size_kb = os.path.getsize(filepath) / 1024
                        print(f"[*] Selected: {filepath} ({file_size_kb:.2f} KB)")
                        self.send_file_p2p(target_ip, filepath)

                    else:
                        print("[-] Selection canceled.")
                except (ValueError, IndexError):
                    print("[!] Invalid ID.")
                    
            elif choice == '3':
                print("\n[*] Broadcasting PING...")
                active_peers = []
                
                for ip in self.known_peers:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1.0) # waiting 1 s 
                        s.connect((ip, self.p2p_port))
                        
                        # sending a 256 bytes to respect the header structure
                        s.sendall("PING".ljust(256, '\x00').encode('utf-8'))
                        s.close()
                        
                        active_peers.append(ip)
                        print(f"  [+] {ip} is ONLINE")
                    except Exception:
                        print(f"  [-] {ip} gave no response. Eliminated!")
                
                # updating the peers 
                self.known_peers = active_peers
                print("[*] Refresh completed.")
                continue
            
            elif choice == '4' or choice == 'quit':
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