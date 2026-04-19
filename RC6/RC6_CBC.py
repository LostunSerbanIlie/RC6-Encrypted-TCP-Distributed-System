import os
import struct
from RC6.RC6_core import RC6

class RC6_CBC:
    """
    Wrapper for the core algorithm for CBC (Cipher Block Chaining) 
    Used to encrypt text/files larger than 16 bytes
    """

    def __init__(self, key_bytes):
        self.block_size = 16

        # initializing the core of the algorithm in order to use it
        self.core = RC6(key_bytes)

    def pad(self, data_bytes):
        """
        Adds padding (PKCS#7) in order to have a multiple of 16 bytes
        """
        # checking how many bytes are missing until the next multiple of 16
        padding_len = self.block_size - (len(data_bytes) % self.block_size)

        # creating a bytes piece with that number (16 - x) in hex
        padding = bytes([padding_len] * padding_len)

        # adding everything at the end of data
        return data_bytes + padding
    
    def unpad(self, data_bytes):
        """
        Strips the padding after decryption
        """

        # we check the value of the last byte
        padding_len = data_bytes[-1]

        # returning the data stripped by data_bytes
        return data_bytes[:-padding_len]
    
    def encrypt(self, plaintext_bytes):
        """
        Encrypts variable-length data using RC6 in CBC mode.
        Returns: Initialization Vector (16 bytes) prepended to the Ciphertext.
        """

        # generating a random initialization vector
        iv = os.urandom(self.block_size)

        # padding until a multiple of 16
        padded_data = self.pad(plaintext_bytes)

        ciphertext = b""

        # prev_blox = chain link, the first is iv
        prev_block = iv

        # slice the data into 16-byte chunks and chain them
        for i in range(0, len(padded_data), self.block_size):
            chunk = padded_data[i : i + self.block_size]

            # XOR between plaintext chunk and the previous chunk
            xored_chunk = bytes(a ^ b for a, b in zip(chunk, prev_block))

            # encrypt the XORed rezult using the RC6 core function
            encrypted_chunk = self.core.encrypt_block(xored_chunk)

            # append to the final result
            ciphertext += encrypted_chunk

            # the current chunk becomes the XOR key for the next
            prev_block = encrypted_chunk

        # the receiver needs the iv for decryption so we attach it as the first thing
        return iv + ciphertext
    
    def decrypt(self, encrypted_data_and_iv):
        """
        Decrypts Cypher Block Chaining mode data
        Expects the first 16 bytes of the input to be the Initialization Vector
        """
        if len(encrypted_data_and_iv)<self.block_size:
            raise ValueError("Data is too short! Initialization Vector missing.")
        
        # exctract the iv and the ciphertext
        iv = encrypted_data_and_iv[:self.block_size]
        actual_ciphertext = encrypted_data_and_iv[self.block_size:]

        plaintext_padded = b""
        prev_block = iv

        # decrypting chunk by chunk
        for i in range(0, len(actual_ciphertext), self.block_size):
            chunk = actual_ciphertext[i : i + self.block_size]

            # run the chunk backwards
            decrypted_chunk = self.core.decrypt_block(chunk)

            # reverse the XOR operation to recover the original plaintext chunk
            plaintext_chunk = bytes(a ^ b for a, b in zip(decrypted_chunk, prev_block))

            plaintext_padded += plaintext_chunk

            # in decrypt the 'prev_block' is the CURRENT ciphertext chunk 
            # BEFORE it was decrypted. We save it for the next round's XOR
            prev_block = chunk

            # remove the PKCS#7 padding and return the clean message
        return self.unpad(plaintext_padded)

    
if __name__ == "__main__":
    print("CBC WRAPPER ENCRYPTION/DECRYPTION TEST")
    
    #  key (must be exactly 16 bytes)
    master_key = b"SECRET_PASSWORD!"
    cbc_engine = RC6_CBC(master_key)
    
    # message that is longer than 16 bytes and requires padding
    long_message = b"This is a highly confidential message sent over the network!"
    
    print(f"Original message length: {len(long_message)} bytes")
    print(f"Original message: '{long_message.decode('utf-8')}'\n")
    
    # ENCRYPTION
    encrypted_payload = cbc_engine.encrypt(long_message)
    print(f"Encrypted payload length (IV + Padded Data): {len(encrypted_payload)} bytes")
    # the encrypted payload to see the noise
    print(f"Encrypted payload (hex preview): {encrypted_payload[:len(encrypted_payload)].hex(' ')}\n")
    
    # DECRYPTION
    decrypted_message = cbc_engine.decrypt(encrypted_payload)
    print(f"Recovered message: '{decrypted_message.decode('utf-8')}'")
    
    if long_message == decrypted_message:
         print("\n[SUCCESS] The CBC Wrapper works.")
    else:
         print("\n[ERROR] Something went wrong in the CBC chaining process.")
    print("=" * 50)