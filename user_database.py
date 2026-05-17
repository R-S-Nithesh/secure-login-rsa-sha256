# =============================================================================
#  user_database.py  —  JSON-based User Storage
#  Subject  : Cryptography and Network Security
#  Purpose  : Simulates a secure user database for the login system
# =============================================================================

import json
import os
from datetime import datetime


DB_FILE = "users_db.json"       # Simulated database file


# -----------------------------------------------------------------------------
#  Core DB Operations
# -----------------------------------------------------------------------------

def _load_db() -> dict:
    """Load the user database from the JSON file."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_db(db: dict):
    """Persist the database back to the JSON file."""
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


# -----------------------------------------------------------------------------
#  User Operations
# -----------------------------------------------------------------------------

def user_exists(username: str) -> bool:
    """Check if a username is already registered."""
    db = _load_db()
    return username.lower() in db


def register_user(username: str, password_hash: str, salt: str,
                  public_key: dict) -> bool:
    """
    Register a new user in the database.

    What is stored:
        - Username (as lookup key, lowercased)
        - SHA-256 hash of the password (NOT the plaintext password)
        - Salt used during hashing
        - RSA public key (e, n) — used to encrypt messages TO this user
        - Registration timestamp

    What is NOT stored:
        - Plaintext password (never stored)
        - RSA private key (never stored on server side)

    Returns:
        True on success, False if username already exists.
    """
    db = _load_db()
    key = username.lower()

    if key in db:
        return False                       # Username taken

    db[key] = {
        "username"      : username,
        "password_hash" : password_hash,
        "salt"          : salt,
        "public_key"    : public_key,      # {exponent: e, modulus: n}
        "registered_at" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "login_count"   : 0,
        "last_login"    : None
    }
    _save_db(db)
    return True


def get_user(username: str) -> dict | None:
    """
    Retrieve a user record from the database.

    Returns:
        User dict on success, None if not found.
    """
    db = _load_db()
    return db.get(username.lower())


def update_login_stats(username: str):
    """Increment login count and update last-login timestamp."""
    db = _load_db()
    key = username.lower()
    if key in db:
        db[key]["login_count"] += 1
        db[key]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _save_db(db)


def list_all_users() -> list:
    """Return a list of all registered usernames."""
    db = _load_db()
    return [v["username"] for v in db.values()]


def delete_user(username: str) -> bool:
    """Remove a user from the database."""
    db = _load_db()
    key = username.lower()
    if key in db:
        del db[key]
        _save_db(db)
        return True
    return False


def display_db_contents():
    """Display the raw database contents (for demo / educational purposes)."""
    db = _load_db()
    print("\n" + "═" * 60)
    print("  DATABASE CONTENTS (users_db.json)")
    print("═" * 60)
    if not db:
        print("  [Empty — no users registered yet]")
    for key, user in db.items():
        print(f"\n  Username   : {user['username']}")
        print(f"  Hash       : {user['password_hash'][:32]}...")
        print(f"  Salt       : {user['salt'][:32]}...")
        print(f"  Public Key : e={user['public_key']['exponent']}, n={str(user['public_key']['modulus'])[:20]}...")
        print(f"  Registered : {user['registered_at']}")
        print(f"  Logins     : {user['login_count']}")
    print("═" * 60 + "\n")
