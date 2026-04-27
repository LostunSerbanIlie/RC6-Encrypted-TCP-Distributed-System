import random

def gcd(a, b):
    """Standard GCD."""
    while b != 0:
        a, b = b, a % b
    return a

def extended_euclid_alg(a, b):
    """
    Extended Euclidean Algorithm for modular inverse.
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_euclid_alg(b % a, a)
        return g, x - (b // a) * y, y 
    
def mod_inverse(e, phi):
    """Finds d such that d * e = 1 mod phi."""
    g, x, y = extended_euclid_alg(e, phi)
    if g != 1:
        raise Exception('Inversul modular nu exista!')
    else:
        return x % phi
    
def is_prime(n, k=5):
    """
    Miller-Rabin primality test for large primes.
    """
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits):
    """Generates a random prime number of given bit size."""
    while True:
        p = random.getrandbits(bits)
        # Ensure the number is odd and has exact bit length
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p
        
def generate_keypair(keysize=1024):
    """
    Generates Public and Private keys.
    """
    print(f"[*] Generating primes p and q ({keysize//2} bits)...")
    p = generate_large_prime(keysize // 2)
    q = generate_large_prime(keysize // 2)

    N = p * q
    phi = (p - 1) * (q - 1)

    # Choose encryption key 'e'
    e = 65537 # Standard safe value (Fermat prime F4)
    if gcd(e, phi) != 1:
        e = random.randrange(3, phi - 1)
        while gcd(e, phi) != 1:
            e = random.randrange(3, phi - 1)

    # Compute private key 'd' using Extended Euclid
    d = mod_inverse(e, phi)

    # Return (Public Key, Private Key)
    return ((e, N), (d, N))

def encrypt(public_key, plaintext_bytes):
    """
    Encrypts data: converts between bytes and math.
    """
    e, N = public_key
    # 1. Convert 16 bytes to integer (M)
    m_int = int.from_bytes(plaintext_bytes, byteorder='big')
    
    # Safety: N must be greater than message M
    if m_int >= N:
        raise ValueError("Message is too big to be encrypted with this N!")
        
    # 2. Math: C = M^e mod N
    # Note: pow() uses efficient exponentiation
    c_int = pow(m_int, e, N)
    
    # 3. Convert large C back to bytes for network
    num_bytes = (N.bit_length() + 7) // 8
    return c_int.to_bytes(num_bytes, byteorder='big')

def decrypt(private_key, ciphertext_bytes):
    """
    Decrypts data.
    """
    d, N = private_key
    # 1. Convert received bytes to integer (C)
    c_int = int.from_bytes(ciphertext_bytes, byteorder='big')
    
    # 2. Math: M = C^d mod N
    m_int = pow(c_int, d, N)
    
    # 3. Convert integer M back to original 16 bytes
    return m_int.to_bytes(16, byteorder='big')


def main():
    print("[RSA] Generating keypair...")
    public_key, private_key = generate_keypair(256)  # increased keysize so all 16-byte test vectors fit
    print(f"Public key: {public_key}\nPrivate key: {private_key}")

    # test vectors: 16-byte messages
    test_vectors = [
        b'\x00' * 16,
        b'\x01' * 16,
        b'\xff' * 16,
        b'Hello, RSA test!',
        b'1234567890abcdef',
        bytes(range(16)),
    ]

    for i, msg in enumerate(test_vectors):
        print(f"\nTest vector {i+1}:")
        print(f"Original: {msg}")
        ct = encrypt(public_key, msg)
        print(f"Encrypted: {ct.hex()}")
        pt = decrypt(private_key, ct)
        print(f"Decrypted: {pt}")
        assert pt == msg, f"Decryption failed for vector {i+1}!"
    print("\nAll test vectors passed.")


if __name__ == "__main__":
    main()