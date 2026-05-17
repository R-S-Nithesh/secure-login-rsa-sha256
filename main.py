# =============================================================================
#  main.py  —  Secure Login System with RSA + SHA-256
#  Subject  : Cryptography and Network Security
#  Authors  : [Your Name]  &  [Partner's Name]
#  USN      : [Your USN]   &  [Partner's USN]
#  College  : MVJ College of Engineering, Bengaluru (VTU)
#  Date     : 2025
# =============================================================================
#
#  SYSTEM OVERVIEW
#  ───────────────
#  This application demonstrates two core cryptographic concepts:
#
#  1. PASSWORD HASHING (SHA-256 + Salt)
#     ▸ Passwords are NEVER stored in plaintext
#     ▸ Each password is hashed with a unique random salt
#     ▸ Login verification re-hashes the input and compares
#
#  2. RSA ENCRYPTION / DECRYPTION
#     ▸ Each user gets a unique RSA key pair on registration
#     ▸ Public key is stored in the database
#     ▸ Private key is shown ONCE to the user (they must save it)
#     ▸ After login, the user can encrypt/decrypt messages
#
# =============================================================================

import sys
import getpass
import time

from rsa_engine      import generate_keypair, encrypt, decrypt, key_to_dict, dict_to_key
from password_hasher import hash_password, verify_password, display_hash_info
from user_database   import (register_user, get_user, user_exists,
                              update_login_stats, display_db_contents, list_all_users)


# =============================================================================
#  UI HELPERS
# =============================================================================

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║        SECURE LOGIN SYSTEM — RSA + SHA-256 HASHING          ║
║        Cryptography & Network Security | VTU                 ║
╚══════════════════════════════════════════════════════════════╝
"""

def clear_line():
    print()

def divider(char="─", width=62):
    print(char * width)

def header(title: str):
    divider("═")
    print(f"  {title}")
    divider("═")

def info(msg):  print(f"  [i] {msg}")
def ok(msg):    print(f"  [✓] {msg}")
def warn(msg):  print(f"  [!] {msg}")
def err(msg):   print(f"  [✗] {msg}")

def pause():
    input("\n  Press ENTER to continue ...")


# =============================================================================
#  FEATURE 1 : REGISTRATION
# =============================================================================

def register():
    header("USER REGISTRATION")

    # ── Username ──────────────────────────────────────────────────────────────
    while True:
        username = input("  Enter username : ").strip()
        if not username:
            warn("Username cannot be empty.")
            continue
        if user_exists(username):
            err(f"Username '{username}' is already taken. Choose another.")
            continue
        break

    # ── Password ──────────────────────────────────────────────────────────────
    while True:
        password = getpass.getpass("  Enter password : ")
        if len(password) < 6:
            warn("Password must be at least 6 characters.")
            continue
        confirm = getpass.getpass("  Confirm password : ")
        if password != confirm:
            err("Passwords do not match. Try again.")
            continue
        break

    print()
    info("Hashing your password with SHA-256 + Salt ...")
    time.sleep(0.5)

    # ── Hash the password ─────────────────────────────────────────────────────
    pw_hash, salt = hash_password(password)
    display_hash_info(password, pw_hash, salt)

    # ── Generate RSA key pair ─────────────────────────────────────────────────
    info("Generating your RSA key pair (this may take a moment) ...")
    pub_key, priv_key = generate_keypair(bits=512)   # 512-bit for demo speed; use 2048 in production

    # ── Store in database (public key only) ───────────────────────────────────
    pub_key_dict = key_to_dict(pub_key, "public")
    success = register_user(username, pw_hash, salt, pub_key_dict)

    if success:
        ok(f"User '{username}' registered successfully!")

        # Show private key — user must save this (we don't store it)
        print("\n" + "!" * 62)
        print("  ⚠  IMPORTANT: SAVE YOUR PRIVATE KEY")
        print("!" * 62)
        print(f"  Private Exponent (d) : {priv_key[0]}")
        print(f"  Modulus (n)          : {priv_key[1]}")
        print("!" * 62)
        print("  This key is NOT stored anywhere. If you lose it,")
        print("  you will NOT be able to decrypt messages.")
        print("!" * 62)
    else:
        err("Registration failed. Please try again.")

    pause()


# =============================================================================
#  FEATURE 2 : LOGIN
# =============================================================================

def login():
    header("USER LOGIN")

    username = input("  Username : ").strip()
    password = getpass.getpass("  Password : ")

    print()
    info("Verifying credentials ...")
    time.sleep(0.6)

    # ── Lookup user ───────────────────────────────────────────────────────────
    user = get_user(username)
    if not user:
        err("Username not found.")
        pause()
        return None

    # ── Verify password ───────────────────────────────────────────────────────
    if verify_password(password, user["password_hash"], user["salt"]):
        ok(f"Login successful! Welcome, {user['username']}.")
        update_login_stats(username)

        # Show verification detail
        print()
        divider()
        info("HOW YOUR LOGIN WAS VERIFIED:")
        info(f"  1. Retrieved salt from DB : {user['salt'][:32]}...")
        info(f"  2. Re-hashed your input   : SHA-256(salt + password)")
        info(f"  3. Compared with stored   : {user['password_hash'][:32]}...")
        info(f"  4. Match result           : ✓ VERIFIED")
        divider()
        pause()
        return user
    else:
        err("Incorrect password. Access denied.")
        pause()
        return None


# =============================================================================
#  FEATURE 3 : RSA ENCRYPT/DECRYPT SESSION
# =============================================================================

def rsa_session(user: dict, private_key: tuple = None):
    """Interactive RSA demo after login."""
    while True:
        header(f"RSA SESSION  —  Logged in as: {user['username']}")
        print("  1. Encrypt a message  (uses your PUBLIC key)")
        print("  2. Decrypt a message  (uses your PRIVATE key)")
        print("  3. View your PUBLIC key")
        print("  4. Back to main menu")
        divider()

        choice = input("  Select [1-4] : ").strip()

        if choice == "1":
            _encrypt_message(user)
        elif choice == "2":
            _decrypt_message(user, private_key)
        elif choice == "3":
            _show_public_key(user)
        elif choice == "4":
            break
        else:
            warn("Invalid choice.")


def _encrypt_message(user: dict):
    header("ENCRYPT MESSAGE (RSA Public Key)")
    pub_key = dict_to_key(user["public_key"])
    message = input("  Enter plaintext message : ").strip()
    if not message:
        warn("Message cannot be empty.")
        pause()
        return
    try:
        ciphertext = encrypt(message, pub_key)
        print()
        ok("Encryption successful!")
        divider()
        info(f"Plaintext  : {message}")
        info(f"Ciphertext : {str(ciphertext)[:60]}...")
        info(f"(Full ciphertext is {len(str(ciphertext))} digits long)")
        divider()
        info("Formula used: C = M^e mod n")
        info(f"  e (public exponent) = {pub_key[0]}")
        info(f"  n (modulus)         = {str(pub_key[1])[:30]}...")
        divider()
        print(f"\n  Full ciphertext (integer):\n  {ciphertext}\n")
    except ValueError as ve:
        err(str(ve))
    pause()


def _decrypt_message(user: dict, private_key: tuple):
    header("DECRYPT MESSAGE (RSA Private Key)")

    if private_key is None:
        warn("No private key loaded for this session.")
        info("Enter your private key manually:")
        try:
            d = int(input("  Private exponent (d) : ").strip())
            n = int(input("  Modulus (n)          : ").strip())
            private_key = (d, n)
        except ValueError:
            err("Invalid key — must be integers.")
            pause()
            return

    try:
        cipher_input = input("  Enter ciphertext (integer) : ").strip()
        ciphertext   = int(cipher_input)
        plaintext    = decrypt(ciphertext, private_key)
        print()
        ok("Decryption successful!")
        divider()
        info(f"Ciphertext : {str(ciphertext)[:50]}...")
        info(f"Plaintext  : {plaintext}")
        divider()
        info("Formula used: M = C^d mod n")
    except Exception as e:
        err(f"Decryption failed: {e}")
    pause()


def _show_public_key(user: dict):
    header("YOUR PUBLIC KEY")
    pub = user["public_key"]
    print(f"  Public Exponent (e) : {pub['exponent']}")
    print(f"  Modulus (n)         : {pub['modulus']}")
    print()
    info("Share this key freely — others use it to encrypt messages TO you.")
    info("Only your PRIVATE key can decrypt those messages.")
    pause()


# =============================================================================
#  FEATURE 4 : ADMIN VIEW (Database Inspector)
# =============================================================================

def admin_view():
    header("DATABASE INSPECTOR (Educational View)")
    users = list_all_users()
    if not users:
        info("No users registered yet.")
        pause()
        return
    display_db_contents()
    pause()


# =============================================================================
#  FEATURE 5 : LIVE RSA DEMO (No login required)
# =============================================================================

def live_demo():
    """Step-by-step RSA demo for viva/presentation."""
    header("LIVE RSA ALGORITHM DEMO")
    print("  This demo walks through RSA step by step.\n")

    info("Generating a fresh RSA key pair ...")
    pub, priv = generate_keypair(bits=256)  # Small keys for fast demo

    e, n = pub
    d, _ = priv

    print(f"\n  Public Key  : (e={e}, n={n})")
    print(f"  Private Key : (d={str(d)[:20]}...)")

    print()
    divider()
    message = input("  Enter a short message to encrypt (max ~20 chars) : ").strip()

    if not message:
        message = "Hello RSA!"

    try:
        print("\n  Encrypting ...")
        ciphertext = encrypt(message, pub)
        ok(f"Encrypted  : {ciphertext}")

        print("\n  Decrypting ...")
        recovered  = decrypt(ciphertext, priv)
        ok(f"Decrypted  : {recovered}")

        if recovered == message:
            print()
            ok("✓ RSA round-trip successful! Original == Decrypted.")
        else:
            err("Mismatch — something went wrong.")
    except ValueError as ve:
        err(str(ve))
        warn("Try a shorter message for 256-bit demo keys.")

    pause()


# =============================================================================
#  MAIN MENU
# =============================================================================

def main_menu():
    print(BANNER)
    while True:
        divider("═")
        print("  MAIN MENU")
        divider("═")
        print("  1. Register a new account")
        print("  2. Login")
        print("  3. Live RSA Demo (viva-friendly)")
        print("  4. View Database (Educational)")
        print("  5. Exit")
        divider()

        choice = input("  Select [1-5] : ").strip()
        print()

        if choice == "1":
            register()

        elif choice == "2":
            user = login()
            if user:
                # Ask if they have their private key handy
                print("  Do you have your private key? (y/n) : ", end="")
                has_key = input().strip().lower()
                priv_key = None
                if has_key == "y":
                    try:
                        d = int(input("  Private exponent (d) : ").strip())
                        n = int(input("  Modulus (n)          : ").strip())
                        priv_key = (d, n)
                    except ValueError:
                        warn("Invalid key entered. Continuing without private key.")
                rsa_session(user, priv_key)

        elif choice == "3":
            live_demo()

        elif choice == "4":
            admin_view()

        elif choice == "5":
            print("  Exiting. Goodbye!\n")
            sys.exit(0)

        else:
            warn("Invalid option. Please choose 1–5.")


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user. Exiting.\n")
        sys.exit(0)
