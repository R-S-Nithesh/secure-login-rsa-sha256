# 🔐 Secure Login System — RSA + SHA-256

> **VTU Cryptography & Network Security | Group Programming Assignment**  
> MVJ College of Engineering, Bengaluru

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-purple)
![License](https://img.shields.io/badge/License-MIT-green)
![VTU](https://img.shields.io/badge/University-VTU-orange)

---

## 📌 About

A **GUI-based Secure Login System** implementing two cryptographic algorithms from scratch:

- 🔑 **RSA Encryption / Decryption** — Asymmetric public-key cryptography
- 🔒 **SHA-256 Password Hashing with Salt** — Secure credential storage

Built using **pure Python standard library only** — no external crypto packages.

---

## 🖥️ Screenshots

| Register Tab | Login Tab |
|---|---|
|<img width="1919" height="990" alt="Register" src="https://github.com/user-attachments/assets/7c98e411-0917-46e8-b10a-3a670f89fcde" />|<img width="1919" height="987" alt="login" src="https://github.com/user-attachments/assets/39c78ea3-6eef-47a0-b651-49e9dc34e632" />|

| RSA Demo Tab | Database Tab |
|---|---|
|<img width="1919" height="982" alt="RSA Demo" src="https://github.com/user-attachments/assets/7ac23fa0-622f-4fc2-8086-4f9bb22abf13" />
|<img width="1919" height="991" alt="DB" src="https://github.com/user-attachments/assets/ce1f0a13-004f-4587-ae33-51e14a5c95ff" />
|

---

## ✨ Features

- ✅ RSA key pair generation from scratch (Miller-Rabin + Extended Euclidean)
- ✅ SHA-256 hashing with cryptographically random 256-bit salt
- ✅ Plaintext passwords **never stored** — only hash + salt persisted
- ✅ Private key shown **once only** — never written to disk
- ✅ Timing-safe password comparison (`hmac.compare_digest`)
- ✅ Live RSA round-trip demo with step-by-step log
- ✅ Educational database inspector showing exactly what is stored
- ✅ Multithreaded GUI — key generation runs in background (non-blocking)
- ✅ Dark themed Tkinter GUI

---

## 📁 Project Structure

```
secure-login-rsa-sha256/
│
├── main_gui.py          # Tkinter GUI — 4 tabs (Register, Login, RSA Demo, Database)
├── rsa_engine.py        # RSA algorithm from scratch (keygen, encrypt, decrypt)
├── password_hasher.py   # SHA-256 + salt hashing and verification
├── user_database.py     # JSON-based user storage
│
├── users_db.json        # Auto-created on first registration (gitignored)
├── screenshots/         # App screenshots for README
├── README.md
└── .gitignore
```

---

## ⚙️ How to Run

### Prerequisites
- Python 3.x (Tkinter is built-in — no pip install needed)

### Run
```bash
git clone https://github.com/YOUR_USERNAME/secure-login-rsa-sha256.git
cd secure-login-rsa-sha256
python main_gui.py
```

---

## 🔬 Algorithm Details

### RSA Key Generation
```
1. Generate two large distinct primes  p  and  q  (Miller-Rabin test)
2. Compute modulus:        n   = p × q
3. Compute totient:        φ(n) = (p-1)(q-1)
4. Choose public exponent: e   = 65537  [gcd(e, φ(n)) = 1]
5. Compute private key:    d   = e⁻¹ mod φ(n)  [Extended Euclidean]
6. Public Key  = (e, n)
7. Private Key = (d, n)
```

### RSA Encrypt / Decrypt
```
Encrypt:  C = M^e mod n   (using public key)
Decrypt:  M = C^d mod n   (using private key)
```

### SHA-256 Password Hashing
```
Registration:  hash = SHA-256(os.urandom(32) + password)
Login:         hash == SHA-256(stored_salt + entered_password) ?
```

---

## 🗄️ What is Stored in the Database

| Field | Stored? | Note |
|---|---|---|
| Username | ✅ Yes | Lookup key |
| Password (plain) | ❌ **NEVER** | Core security principle |
| SHA-256 Hash | ✅ Yes | 64 hex characters |
| Salt | ✅ Yes | 256-bit random, unique per user |
| RSA Public Key (e, n) | ✅ Yes | For encrypting messages to user |
| RSA Private Key (d) | ❌ **NEVER** | Shown once, never persisted |

---

## 👨‍💻 Authors

| Name | USN |
|---|---|
| [Student 1 Name] | [USN1] |
| [Student 2 Name] | [USN2] |

**College:** MVJ College of Engineering, Bengaluru  
**University:** Visvesvaraya Technological University (VTU)  
**Subject:** Cryptography and Network Security

---

## 📚 References

1. William Stallings, *Cryptography and Network Security*, 8th Ed., Pearson, 2019
2. R. Rivest, A. Shamir, L. Adleman — *A Method for Obtaining Digital Signatures*, ACM 1978
3. NIST FIPS PUB 180-4 — Secure Hash Standard (SHA-256)
4. OWASP Password Storage Cheat Sheet

---

## 📄 License

MIT License — free to use for educational purposes.
