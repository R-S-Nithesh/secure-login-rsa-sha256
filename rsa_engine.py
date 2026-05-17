# =============================================================================
#  rsa_engine.py  —  RSA Cryptographic Algorithm (From Scratch)
#  Subject  : Cryptography and Network Security
#  Topic    : RSA Encryption & Decryption
# =============================================================================

import random
import math


# -----------------------------------------------------------------------------
#  STEP 1 : Primality Testing (Miller-Rabin)
# -----------------------------------------------------------------------------

def is_prime(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    Returns True if n is (probably) prime, False if definitely composite.

    Parameters:
        n  : Number to test
        k  : Number of rounds (higher = more accurate)
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)                   # a^d mod n

        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False                   # Composite

    return True                            # Probably prime


def generate_prime(bits: int = 512) -> int:
    """Generate a random prime number of the given bit-length."""
    print(f"    [*] Searching for a {bits}-bit prime ...", end=" ", flush=True)
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1   # Force MSB=1 and odd
        if is_prime(candidate):
            print("Found!")
            return candidate


# -----------------------------------------------------------------------------
#  STEP 2 : Greatest Common Divisor & Modular Inverse
# -----------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for GCD."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e: int, phi: int) -> int:
    """
    Extended Euclidean Algorithm.
    Finds d such that (e * d) % phi == 1.
    This d is the RSA private exponent.
    """
    def _extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = _extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    g, x, _ = _extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist — gcd(e, φ(n)) ≠ 1")
    return x % phi


# -----------------------------------------------------------------------------
#  STEP 3 : Key Generation
# -----------------------------------------------------------------------------

def generate_keypair(bits: int = 512):
    """
    Generate RSA public & private key pair.

    Algorithm:
        1. Choose two large distinct primes  p  and  q
        2. Compute n  = p × q            (modulus)
        3. Compute φ  = (p−1)(q−1)      (Euler's totient)
        4. Choose e such that 1 < e < φ and gcd(e, φ) = 1
        5. Compute d  = e⁻¹ mod φ       (private exponent)

    Returns:
        public_key  : (e, n)
        private_key : (d, n)
    """
    print("\n[RSA] Generating key pair ...")

    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n   = p * q
    phi = (p - 1) * (q - 1)

    # e = 65537 is the standard public exponent (prime, and fast in binary)
    e = 65537
    if gcd(e, phi) != 1:
        # Fallback: find smallest valid e
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    print(f"    [✓] Modulus n  = {str(n)[:30]}...  ({n.bit_length()} bits)")
    print(f"    [✓] Public  e  = {e}")
    print(f"    [✓] Private d  = {str(d)[:30]}...")
    print("[RSA] Key generation complete.\n")

    return (e, n), (d, n)


# -----------------------------------------------------------------------------
#  STEP 4 : Encrypt & Decrypt
# -----------------------------------------------------------------------------

def encrypt(plaintext: str, public_key: tuple) -> int:
    """
    Encrypt a plaintext string using the RSA public key.

    Formula: C = M^e mod n
        where M = integer representation of the message.
    """
    e, n = public_key
    message_bytes = plaintext.encode("utf-8")
    M = int.from_bytes(message_bytes, byteorder="big")

    if M >= n:
        raise ValueError(
            "Message is too long for this key size. "
            "Use a larger key or encrypt in smaller chunks."
        )

    C = pow(M, e, n)    # Python's pow() with 3 args uses fast modular exponentiation
    return C


def decrypt(ciphertext_int: int, private_key: tuple) -> str:
    """
    Decrypt a ciphertext integer using the RSA private key.

    Formula: M = C^d mod n
    """
    d, n = private_key
    M = pow(ciphertext_int, d, n)
    byte_length = (M.bit_length() + 7) // 8
    message_bytes = M.to_bytes(byte_length, byteorder="big")
    return message_bytes.decode("utf-8")


# -----------------------------------------------------------------------------
#  STEP 5 : Key Export / Import (simple JSON-serialisable format)
# -----------------------------------------------------------------------------

def key_to_dict(key: tuple, key_type: str) -> dict:
    """Convert a key tuple to a JSON-serialisable dict."""
    exponent, modulus = key
    return {
        "type"    : key_type,
        "exponent": exponent,
        "modulus" : modulus
    }


def dict_to_key(d: dict) -> tuple:
    """Reconstruct a key tuple from a dict."""
    return (d["exponent"], d["modulus"])
