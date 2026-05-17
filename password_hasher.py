# =============================================================================
#  password_hasher.py  —  Password Hashing using SHA-256 with Salt
#  Subject  : Cryptography and Network Security
#  Topic    : Password Encryption & Login Verification using Hashing
# =============================================================================

import hashlib
import os
import binascii


# -----------------------------------------------------------------------------
#  Salt Generation
# -----------------------------------------------------------------------------

def generate_salt(byte_length: int = 32) -> str:
    """
    Generate a cryptographically secure random salt.

    Why salt?
        Without salt, identical passwords produce identical hashes.
        An attacker can use precomputed rainbow tables to crack them.
        Salt makes every hash unique — even for the same password.

    Parameters:
        byte_length : Length of random bytes (default 32 → 256-bit salt)

    Returns:
        Hex-encoded salt string (64 hex characters for 32 bytes)
    """
    raw_bytes = os.urandom(byte_length)        # Cryptographically secure RNG
    return binascii.hexlify(raw_bytes).decode("utf-8")


# -----------------------------------------------------------------------------
#  Hash a Password
# -----------------------------------------------------------------------------

def hash_password(password: str, salt: str = None) -> tuple:
    """
    Hash a password using SHA-256 with a random salt.

    Algorithm:
        1. Generate a random 256-bit salt (if not provided)
        2. Concatenate: salted_input = salt + password
        3. Compute:    hash = SHA-256(salted_input)
        4. Return (hash_hex, salt)

    Parameters:
        password : The plaintext password string
        salt     : Existing salt (used during login verification)

    Returns:
        (hashed_password_hex, salt_hex) as a tuple of strings
    """
    if salt is None:
        salt = generate_salt()

    # Concatenate salt + password and encode to bytes
    salted_input = (salt + password).encode("utf-8")

    # SHA-256 produces a 256-bit (32-byte) digest
    digest = hashlib.sha256(salted_input).hexdigest()

    return digest, salt


# -----------------------------------------------------------------------------
#  Verify a Password
# -----------------------------------------------------------------------------

def verify_password(plaintext_password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify a plaintext password against a stored hash.

    Process:
        1. Re-hash the provided password using the SAME salt that was stored
        2. Compare the newly computed hash with the stored hash
        3. Use constant-time comparison to prevent timing attacks

    Parameters:
        plaintext_password : Password entered by the user at login
        stored_hash        : Hash stored in the database at registration
        stored_salt        : Salt stored alongside the hash

    Returns:
        True if password matches, False otherwise
    """
    computed_hash, _ = hash_password(plaintext_password, stored_salt)

    # hmac.compare_digest prevents timing-based side-channel attacks
    import hmac
    return hmac.compare_digest(computed_hash, stored_hash)


# -----------------------------------------------------------------------------
#  Utility : Display Hash Info
# -----------------------------------------------------------------------------

def display_hash_info(password: str, hashed: str, salt: str):
    """Pretty-print hashing details for educational display."""
    print("\n" + "─" * 60)
    print("  PASSWORD HASHING DETAILS (SHA-256 + Salt)")
    print("─" * 60)
    print(f"  Plaintext Password : {password}")
    print(f"  Salt (256-bit)     : {salt[:32]}...")
    print(f"  SHA-256 Hash       : {hashed[:32]}...")
    print(f"  Full Hash (hex)    : {hashed}")
    print(f"  Hash Length        : {len(hashed) * 4} bits ({len(hashed)} hex chars)")
    print("─" * 60)
    print("  [!] Password is NEVER stored — only the hash is saved.")
    print("─" * 60 + "\n")
