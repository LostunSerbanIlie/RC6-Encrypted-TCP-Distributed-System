import struct


class RC6:
    """
    Implements the RC6 algorithm RC6 - w/r/b, where:
    w = word size
    r = rounds
    b = bytes of key

    """
    def __init__(self, key_bytes):
        """
        Initializes the RC6 cipher RC6-32/20/16
        Waits for a key of 16 bytes (128 bits) to be provided
        """

        if len(key_bytes) !=16:
            raise ValueError("The inserted key must be exactly 16 bytes (128 bits)!")
        
        # pseudo-random "magical" constants used for initializing the S array
        self.P32 = 0xB7E15163 # constant e distribution
        self.Q32 = 0x9E3779B9 # golden ratio

        # mask to keep number on 32 bits
        self.MASK32 = 0xFFFFFFFF
        
        # subkeys array
        self.S = self.generate_key_schedule(key_bytes)

    def rotate_left(self, x, y):
        """Circular rotation left 32 bits"""
        y = y & 31 # shifting 31 positions max
        return ((x << y) | (x >> (32-y))) & self.MASK32
    
    def rotate_right(self, x, y):
        """Circular rotation left 32 bits"""
        y = y & 31
        return ((x >> y) | (x << (32 - y))) & self.MASK32
    
    # I. key schedule logic
    def generate_key_schedule(self, key):
        """
        Transforms the 16 bytes password into 44 (2*r + 4) 32-bit subkeys

        """

        # splits the 16 bytes pass into a 4 words array (32 bitseach)
        L = list(struct.unpack('<4I', key))
        c = 4 # 4 words in L

        # S array initialising
        S = [0] * 44
        S[0] = self.P32
        
        for i in range (1, 44):
            S[i] = (S[i - 1] + self.Q32) & self.MASK32

        # mixing the password (L) with the array (S)
        A = B = i = j = 0

        # executing for 3 * max(c,44) times - 132 iterations
        v = 3 * max (c, 44)
        
        for _ in range (v):
            # S[i] = (S[i] + A + B) <<< 3
            A = S[i] = self.rotate_left((S[i] + A + B) & self.MASK32, 3)

            # L[j] = (L[j] + A + B) <<< (A + B)
            B = L[j] = self.rotate_left((L[j] + A + B) & self.MASK32, (A + B))

            i = (i + 1) % 44
            j = (j + 1) % c
        
        return S
    
    # II. encrypt block
    def encrypt_block(self, plaintext_bytes):
        """
        Encrypts a fixed-size 16 bytes block
        """

        if len(plaintext_bytes) != 16:
            raise ValueError("The block size must be 16 bytes!")
        
        # unpack the 16 bytes in 4 registers (A, B, C, D) - 32 bits
        A, B, C, D = struct.unpack('<4I', plaintext_bytes)

        # pre-whitening
        B = (B + self.S[0]) & self.MASK32
        D = (D + self.S[1]) & self.MASK32

        # 20 rounds - Generalized Feistel Network
        # t and u f(x) = x(2x+1)
        for i in range(1, 21):
            t = self.rotate_left((B * ((2 * B) + 1)) & self.MASK32, 5)
            u = self.rotate_left((D * ((2 * D) + 1)) & self.MASK32, 5)

            # data dependent rotation and key addition
            A = (self.rotate_left(A ^ t, u) + self.S[2 * i]) & self.MASK32
            C = (self.rotate_left(C ^ u, t) + self.S[2 * i + 1]) & self.MASK32

            # register permutation
            A, B, C, D = B, C, D, A

        # post-whitening
        A = (A + self.S[42]) & self.MASK32
        C = (C + self.S[43]) & self.MASK32

        # repacking the 4 register into an encrypted 16 bytes block
        return struct.pack('<4I', A, B, C, D)


if __name__ == "__main__":
    # KEY SCHEDULE GENERATION TEST
    print("KEY SCHEDULE GENERATION TEST: ")

    # exactly 16 characters (128-bits)
    test_password = b"SECRET_PASSWORD!"

    # creating the RC6 object (this automatically triggers generate_key_schedule)
    rc6 = RC6(test_password)

    print("[SUCCESS] Successfully generated all 44 (2 * r + 4) subkeys!")
    print(f"Original password: {test_password}\n")

    print("The keys that were generated: ")
    for idx in range (44):
        # formatted to look like memory addresses/registers
        print(f"S[{idx:02d}] = 0x{rc6.S[idx]:08x}")
    
    print("First test ended.")
    print("=" * 40)


    ################################################################
    # ENCRYPTION TEST
    user_key_hex = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    plaintext_hex = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    expected_ciphertext_hex = "8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e"

    user_key_hex2 = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78"
    plaintext_hex2 = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1"
    expected_ciphertext_hex2 = "52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18"

    print("\nENCRYPTION TEST: ")
    print("Test Vector 1 (MIT Paper)")
    key = bytes.fromhex(user_key_hex)
    plaintext = bytes.fromhex(plaintext_hex)
    rc6 = RC6(key)

    # plaintext encryption
    ct_bytes = rc6.encrypt_block(plaintext)
    print(f"Plaintext received:  {plaintext.hex(' ')}")
    expected_formatted = bytes.fromhex(expected_ciphertext_hex).hex(' ')
    print(f"Expected ciphertext: {expected_formatted}")
    print(f"Obtained ciphertext: {ct_bytes.hex(' ')}")

    print("\nTest Vector 2 (MIT Paper)")
    key2 = bytes.fromhex(user_key_hex2)
    plaintext2 = bytes.fromhex(plaintext_hex2)
    rc62 = RC6(key2)

    ct_bytes2 = rc62.encrypt_block(plaintext2)
    print(f"Plaintext received:  {plaintext2.hex(' ')}")
    expected_formatted2 = bytes.fromhex(expected_ciphertext_hex2).hex(' ')
    print(f"Expected ciphertext: {expected_formatted2}")
    print(f"Obtained ciphertext: {ct_bytes2.hex(' ')}")

    if (ct_bytes.hex(' ') == expected_formatted) and (ct_bytes2.hex(' ') == expected_formatted2):
        print("[SUCCESS] The results match the expected ones.")
        print("Second test ended.")
        print("=" * 40)
    else:
        print("[ERROR] The results don't match the expected ones. Retry.")