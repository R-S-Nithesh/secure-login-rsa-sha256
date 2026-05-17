# =============================================================================
#  main_gui.py  —  Secure Login System | RSA + SHA-256  (GUI Version)
#  Subject  : Cryptography and Network Security
#  Authors  : [Your Name]  &  [Partner's Name]
#  College  : MVJ College of Engineering, Bengaluru (VTU)
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time

from rsa_engine      import generate_keypair, encrypt, decrypt, key_to_dict, dict_to_key
from password_hasher import hash_password, verify_password
from user_database   import (register_user, get_user, user_exists,
                              update_login_stats, list_all_users, display_db_contents,
                              _load_db)

# ── Colour palette ────────────────────────────────────────────────────────────
BG       = "#1e1e2e"
PANEL    = "#2a2a3d"
ACCENT   = "#7c3aed"
ACCENT2  = "#a855f7"
SUCCESS  = "#22c55e"
DANGER   = "#ef4444"
TEXT     = "#e2e8f0"
SUBTEXT  = "#94a3b8"
ENTRY_BG = "#16213e"
BORDER   = "#3b3b5c"

FONT_H   = ("Consolas", 15, "bold")
FONT_B   = ("Consolas", 10, "bold")
FONT_N   = ("Consolas", 10)
FONT_S   = ("Consolas",  9)


# =============================================================================
#  MAIN APPLICATION
# =============================================================================

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Login System — RSA + SHA-256 | VTU Crypto Assignment")
        self.geometry("900x680")
        self.minsize(860, 640)
        self.configure(bg=BG)
        self.resizable(True, True)

        # Shared state
        self.logged_in_user = None
        self.session_priv_key = None

        self._build_ui()

    # ──────────────────────────────────────────────────────────────────────────
    #  BUILD UI
    # ──────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=ACCENT, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🔐  SECURE LOGIN SYSTEM",
                 font=("Consolas", 16, "bold"), bg=ACCENT, fg="white").pack()
        tk.Label(hdr, text="RSA Encryption  +  SHA-256 Password Hashing  |  Two Cryptographic Algorithms",
                 font=FONT_S, bg=ACCENT, fg="#ddd6fe").pack()

        # ── Notebook tabs ─────────────────────────────────────────────────────
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",        background=BG,    borderwidth=0)
        style.configure("TNotebook.Tab",    background=PANEL, foreground=SUBTEXT,
                        font=FONT_B, padding=[18, 8])
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        self.tab_register = self._make_frame()
        self.tab_login    = self._make_frame()
        self.tab_rsa      = self._make_frame()
        self.tab_db       = self._make_frame()

        self.nb.add(self.tab_register, text=" 📝  Register ")
        self.nb.add(self.tab_login,    text=" 🔑  Login ")
        self.nb.add(self.tab_rsa,      text=" 🛡  RSA Demo ")
        self.nb.add(self.tab_db,       text=" 🗄  Database ")

        self._build_register_tab()
        self._build_login_tab()
        self._build_rsa_tab()
        self._build_db_tab()

        # ── Status bar ────────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Ready.")
        bar = tk.Frame(self, bg=PANEL, pady=4)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(bar, textvariable=self.status_var,
                 font=FONT_S, bg=PANEL, fg=SUBTEXT, anchor="w", padx=10).pack(fill=tk.X)

    def _make_frame(self):
        f = tk.Frame(self.nb, bg=BG)
        return f

    # ──────────────────────────────────────────────────────────────────────────
    #  REGISTER TAB
    # ──────────────────────────────────────────────────────────────────────────

    def _build_register_tab(self):
        p = self.tab_register
        left = tk.Frame(p, bg=BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=16)
        right = tk.Frame(p, bg=PANEL, width=340)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(0,12), pady=12)
        right.pack_propagate(False)

        # ── Form ──────────────────────────────────────────────────────────────
        self._section(left, "CREATE AN ACCOUNT")

        self._label(left, "Username")
        self.reg_user = self._entry(left)

        self._label(left, "Password")
        self.reg_pass = self._entry(left, show="●")

        self._label(left, "Confirm Password")
        self.reg_pass2 = self._entry(left, show="●")

        self._label(left, "RSA Key Size")
        self.reg_keysize = ttk.Combobox(left, values=["256-bit (fast demo)",
                                                       "512-bit (recommended)",
                                                       "1024-bit (strong)"],
                                        state="readonly", font=FONT_N,
                                        background=ENTRY_BG, foreground=TEXT)
        self.reg_keysize.set("512-bit (recommended)")
        self.reg_keysize.pack(fill=tk.X, pady=(0,10))

        self.reg_btn = self._button(left, "⚡  Register", self._do_register)

        self.reg_status = tk.Label(left, text="", font=FONT_S, bg=BG, fg=SUBTEXT,
                                   wraplength=380, justify=tk.LEFT)
        self.reg_status.pack(fill=tk.X, pady=4)

        # ── Info panel ────────────────────────────────────────────────────────
        self._info_panel(right, "How Registration Works",
            "1. Your password is NEVER stored.\n\n"
            "2. A random 256-bit SALT is generated.\n\n"
            "3. SHA-256 hash = SHA-256(salt + password).\n\n"
            "4. An RSA key pair is generated.\n\n"
            "5. Only the HASH, SALT, and PUBLIC KEY are saved.\n\n"
            "6. Your PRIVATE KEY is shown once — save it!")

        # ── Private key display ───────────────────────────────────────────────
        self._label(right, "⚠  Your Private Key (save this!)", fg=ACCENT2)
        self.priv_key_box = scrolledtext.ScrolledText(
            right, height=7, font=("Consolas", 8),
            bg=ENTRY_BG, fg="#facc15", relief=tk.FLAT, wrap=tk.WORD)
        self.priv_key_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0,8))
        self.priv_key_box.insert(tk.END, "Private key will appear here after registration.")
        self.priv_key_box.config(state=tk.DISABLED)

    # ──────────────────────────────────────────────────────────────────────────
    #  LOGIN TAB
    # ──────────────────────────────────────────────────────────────────────────

    def _build_login_tab(self):
        p = self.tab_login
        left = tk.Frame(p, bg=BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=16)
        right = tk.Frame(p, bg=PANEL, width=340)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(0,12), pady=12)
        right.pack_propagate(False)

        self._section(left, "LOGIN TO YOUR ACCOUNT")

        self._label(left, "Username")
        self.login_user = self._entry(left)

        self._label(left, "Password")
        self.login_pass = self._entry(left, show="●")

        self._button(left, "🔓  Login", self._do_login)

        self.login_status = tk.Label(left, text="", font=FONT_S, bg=BG,
                                     fg=SUBTEXT, wraplength=380, justify=tk.LEFT)
        self.login_status.pack(fill=tk.X, pady=4)

        # ── Verification detail ───────────────────────────────────────────────
        self._label(left, "Verification Detail")
        self.login_log = scrolledtext.ScrolledText(
            left, height=8, font=FONT_S,
            bg=ENTRY_BG, fg=TEXT, relief=tk.FLAT)
        self.login_log.pack(fill=tk.BOTH, expand=True)

        self._info_panel(right, "How Login Works",
            "1. Your username is used to find your record.\n\n"
            "2. The stored SALT is retrieved.\n\n"
            "3. SHA-256(salt + entered_password) is computed.\n\n"
            "4. The result is compared with the stored hash.\n\n"
            "5. If they match → Access Granted ✓\n\n"
            "6. Timing-safe comparison prevents side-channel attacks.")

        self._label(right, "Session Status")
        self.session_label = tk.Label(right, text="● Not logged in",
                                      font=FONT_B, bg=PANEL, fg=DANGER)
        self.session_label.pack(anchor=tk.W, padx=10)

    # ──────────────────────────────────────────────────────────────────────────
    #  RSA DEMO TAB
    # ──────────────────────────────────────────────────────────────────────────

    def _build_rsa_tab(self):
        p = self.tab_rsa
        top = tk.Frame(p, bg=BG)
        top.pack(fill=tk.X, padx=20, pady=12)

        self._section(top, "RSA ENCRYPTION / DECRYPTION")

        # ── Encrypt section ───────────────────────────────────────────────────
        enc_frame = tk.LabelFrame(p, text=" Encrypt Message (Public Key) ",
                                  bg=BG, fg=ACCENT2, font=FONT_B,
                                  relief=tk.GROOVE, bd=1)
        enc_frame.pack(fill=tk.X, padx=20, pady=4)

        self._label(enc_frame, "Plaintext Message")
        self.enc_input = self._entry(enc_frame)
        self._button(enc_frame, "🔒  Encrypt", self._do_encrypt, width=18)

        self._label(enc_frame, "Ciphertext (integer)")
        self.enc_output = scrolledtext.ScrolledText(
            enc_frame, height=3, font=("Consolas", 8),
            bg=ENTRY_BG, fg="#86efac", relief=tk.FLAT)
        self.enc_output.pack(fill=tk.X, padx=8, pady=(0,8))

        # ── Decrypt section ───────────────────────────────────────────────────
        dec_frame = tk.LabelFrame(p, text=" Decrypt Message (Private Key) ",
                                  bg=BG, fg=ACCENT2, font=FONT_B,
                                  relief=tk.GROOVE, bd=1)
        dec_frame.pack(fill=tk.X, padx=20, pady=4)

        self._label(dec_frame, "Ciphertext (paste integer)")
        self.dec_input = scrolledtext.ScrolledText(
            dec_frame, height=3, font=("Consolas", 8),
            bg=ENTRY_BG, fg=TEXT, relief=tk.FLAT)
        self.dec_input.pack(fill=tk.X, padx=8, pady=(0,4))

        self._label(dec_frame, "Private Key d (from registration)")
        self.dec_d = self._entry(dec_frame)
        self._label(dec_frame, "Modulus n")
        self.dec_n = self._entry(dec_frame)

        self._button(dec_frame, "🔓  Decrypt", self._do_decrypt, width=18)

        self._label(dec_frame, "Decrypted Plaintext")
        self.dec_output = self._entry(dec_frame, state=tk.DISABLED)

        # ── Quick RSA Demo ────────────────────────────────────────────────────
        demo_frame = tk.LabelFrame(p, text=" Quick RSA Round-Trip Demo ",
                                   bg=BG, fg=ACCENT2, font=FONT_B,
                                   relief=tk.GROOVE, bd=1)
        demo_frame.pack(fill=tk.X, padx=20, pady=4)

        row = tk.Frame(demo_frame, bg=BG)
        row.pack(fill=tk.X, padx=8, pady=6)
        self._label(row, "Message", pack=False).pack(side=tk.LEFT)
        self.demo_msg = tk.Entry(row, font=FONT_N, bg=ENTRY_BG, fg=TEXT,
                                 insertbackground=TEXT, relief=tk.FLAT, width=28)
        self.demo_msg.insert(0, "Hello VTU!")
        self.demo_msg.pack(side=tk.LEFT, padx=8)
        self._button(row, "▶  Run Demo", self._do_quick_demo, width=14, pack=False).pack(side=tk.LEFT)

        self.demo_log = scrolledtext.ScrolledText(
            demo_frame, height=5, font=FONT_S,
            bg=ENTRY_BG, fg=TEXT, relief=tk.FLAT)
        self.demo_log.pack(fill=tk.X, padx=8, pady=(0,8))

    # ──────────────────────────────────────────────────────────────────────────
    #  DATABASE TAB
    # ──────────────────────────────────────────────────────────────────────────

    def _build_db_tab(self):
        p = self.tab_db
        top = tk.Frame(p, bg=BG)
        top.pack(fill=tk.X, padx=20, pady=10)
        self._section(top, "DATABASE INSPECTOR  (Educational View)")

        row = tk.Frame(p, bg=BG)
        row.pack(fill=tk.X, padx=20, pady=4)
        self._button(row, "🔄  Refresh", self._refresh_db, width=14, pack=False).pack(side=tk.LEFT, padx=4)

        self.db_text = scrolledtext.ScrolledText(
            p, font=("Consolas", 9),
            bg=ENTRY_BG, fg=TEXT, relief=tk.FLAT)
        self.db_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=8)
        self._refresh_db()

    # ──────────────────────────────────────────────────────────────────────────
    #  ACTIONS
    # ──────────────────────────────────────────────────────────────────────────

    def _do_register(self):
        username = self.reg_user.get().strip()
        password = self.reg_pass.get()
        confirm  = self.reg_pass2.get()
        keysize_str = self.reg_keysize.get()
        bits = {"256": 256, "512": 512, "1024": 1024}.get(keysize_str.split("-")[0], 512)

        if not username:
            return self._set(self.reg_status, "Username cannot be empty.", DANGER)
        if user_exists(username):
            return self._set(self.reg_status, f"Username '{username}' is already taken.", DANGER)
        if len(password) < 6:
            return self._set(self.reg_status, "Password must be at least 6 characters.", DANGER)
        if password != confirm:
            return self._set(self.reg_status, "Passwords do not match.", DANGER)

        self._set(self.reg_status, "Hashing password...", SUBTEXT)
        self.reg_btn.config(state=tk.DISABLED)

        def _worker():
            pw_hash, salt = hash_password(password)
            self._set(self.reg_status, "Generating RSA key pair...", SUBTEXT)
            pub_key, priv_key = generate_keypair(bits=bits)
            pub_dict = key_to_dict(pub_key, "public")
            ok = register_user(username, pw_hash, salt, pub_dict)

            if ok:
                d, n = priv_key
                priv_text = (f"=== PRIVATE KEY — KEEP SECRET ===\n"
                             f"d (exponent):\n{d}\n\n"
                             f"n (modulus):\n{n}\n"
                             f"=================================")
                self.priv_key_box.config(state=tk.NORMAL)
                self.priv_key_box.delete("1.0", tk.END)
                self.priv_key_box.insert(tk.END, priv_text)
                self.priv_key_box.config(state=tk.DISABLED)
                self._set(self.reg_status,
                          f"✓ '{username}' registered! Save your private key →", SUCCESS)
                self._refresh_db()
                self.status_var.set(f"Registered: {username}")
            else:
                self._set(self.reg_status, "Registration failed.", DANGER)

            self.reg_btn.config(state=tk.NORMAL)

        threading.Thread(target=_worker, daemon=True).start()

    def _do_login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get()

        if not username or not password:
            return self._set(self.login_status, "Enter username and password.", DANGER)

        user = get_user(username)
        if not user:
            self._log(self.login_log, f"[✗] User '{username}' not found in database.\n", DANGER)
            return self._set(self.login_status, "User not found.", DANGER)

        self._log(self.login_log, f"[i] Found user: {username}\n", SUBTEXT)
        self._log(self.login_log, f"[i] Salt retrieved: {user['salt'][:32]}...\n", SUBTEXT)
        self._log(self.login_log, "[i] Re-hashing entered password with stored salt...\n", SUBTEXT)

        match = verify_password(password, user["password_hash"], user["salt"])

        if match:
            computed, _ = hash_password(password, user["salt"])
            self._log(self.login_log, f"[i] Computed hash : {computed[:32]}...\n", SUBTEXT)
            self._log(self.login_log, f"[i] Stored hash   : {user['password_hash'][:32]}...\n", SUBTEXT)
            self._log(self.login_log, "[✓] Hashes MATCH — Access Granted!\n", SUCCESS)

            self.logged_in_user = user
            update_login_stats(username)
            self._set(self.login_status, f"✓ Welcome, {user['username']}!", SUCCESS)
            self.session_label.config(text=f"● Logged in as: {username}", fg=SUCCESS)
            self.status_var.set(f"Active session: {username}")
            messagebox.showinfo("Login Successful", f"Welcome, {user['username']}!\n\nYou can now use the RSA tab.")
            self.nb.select(self.tab_rsa)
        else:
            self._log(self.login_log, "[✗] Hashes DO NOT match — Access Denied.\n", DANGER)
            self._set(self.login_status, "✗ Incorrect password.", DANGER)

    def _do_encrypt(self):
        if not self.logged_in_user:
            return messagebox.showwarning("Not Logged In", "Please login first.")
        message = self.enc_input.get().strip()
        if not message:
            return messagebox.showwarning("Empty", "Enter a message to encrypt.")
        try:
            pub_key = dict_to_key(self.logged_in_user["public_key"])
            cipher  = encrypt(message, pub_key)
            self.enc_output.config(state=tk.NORMAL)
            self.enc_output.delete("1.0", tk.END)
            self.enc_output.insert(tk.END, str(cipher))
            self.enc_output.config(state=tk.DISABLED)
            # Auto-fill decrypt input
            self.dec_input.config(state=tk.NORMAL)
            self.dec_input.delete("1.0", tk.END)
            self.dec_input.insert(tk.END, str(cipher))
            self.status_var.set("Message encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def _do_decrypt(self):
        cipher_str = self.dec_input.get("1.0", tk.END).strip()
        d_str      = self.dec_d.get().strip()
        n_str      = self.dec_n.get().strip()

        if not cipher_str or not d_str or not n_str:
            return messagebox.showwarning("Missing Input", "Fill in ciphertext, d, and n.")
        try:
            priv_key  = (int(d_str), int(n_str))
            plaintext = decrypt(int(cipher_str), priv_key)
            self.dec_output.config(state=tk.NORMAL)
            self.dec_output.delete(0, tk.END)
            self.dec_output.insert(0, plaintext)
            self.dec_output.config(state=tk.DISABLED)
            self.status_var.set("Decryption successful.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed:\n{e}")

    def _do_quick_demo(self):
        msg = self.demo_msg.get().strip() or "Hello VTU!"
        self.demo_log.delete("1.0", tk.END)

        def _worker():
            self._log(self.demo_log, f"[1] Plaintext      : {msg}\n", TEXT)
            self._log(self.demo_log, "[2] Generating 256-bit RSA key pair...\n", SUBTEXT)
            pub, priv = generate_keypair(bits=256)
            e, n = pub
            d, _ = priv
            self._log(self.demo_log, f"[3] Public key     : e={e}, n={str(n)[:30]}...\n", SUBTEXT)
            self._log(self.demo_log, f"[4] Private key    : d={str(d)[:30]}...\n", SUBTEXT)
            try:
                cipher = encrypt(msg, pub)
                self._log(self.demo_log, f"[5] Ciphertext     : {str(cipher)[:50]}...\n", "#facc15")
                recovered = decrypt(cipher, priv)
                self._log(self.demo_log, f"[6] Decrypted      : {recovered}\n", SUCCESS)
                match = "✓ MATCH" if recovered == msg else "✗ MISMATCH"
                self._log(self.demo_log, f"[7] Verification   : {match}\n", SUCCESS)
            except ValueError as ve:
                self._log(self.demo_log, f"[!] {ve}\n", DANGER)

        threading.Thread(target=_worker, daemon=True).start()

    def _refresh_db(self):
        self.db_text.delete("1.0", tk.END)
        db = _load_db()
        if not db:
            self.db_text.insert(tk.END, "  [Empty — no users registered yet]\n")
            return
        sep = "─" * 68 + "\n"
        self.db_text.insert(tk.END, sep)
        self.db_text.insert(tk.END, f"  {'FIELD':<22} VALUE\n")
        self.db_text.insert(tk.END, sep)
        for key, user in db.items():
            self.db_text.insert(tk.END, f"\n  {'Username':<22} {user['username']}\n")
            self.db_text.insert(tk.END, f"  {'Password Hash':<22} {user['password_hash'][:40]}...\n")
            self.db_text.insert(tk.END, f"  {'Salt':<22} {user['salt'][:40]}...\n")
            pk = user['public_key']
            self.db_text.insert(tk.END, f"  {'Public e':<22} {pk['exponent']}\n")
            self.db_text.insert(tk.END, f"  {'Public n':<22} {str(pk['modulus'])[:40]}...\n")
            self.db_text.insert(tk.END, f"  {'Registered':<22} {user['registered_at']}\n")
            self.db_text.insert(tk.END, f"  {'Login Count':<22} {user['login_count']}\n")
            self.db_text.insert(tk.END, sep)
        self.db_text.insert(tk.END, f"\n  [!] Plaintext passwords are NEVER stored.\n")

    # ──────────────────────────────────────────────────────────────────────────
    #  WIDGET HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _section(self, parent, text):
        tk.Label(parent, text=text, font=FONT_H,
                 bg=BG if parent.cget("bg") == BG else PANEL,
                 fg=ACCENT2).pack(anchor=tk.W, pady=(0, 10))

    def _label(self, parent, text, fg=SUBTEXT, pack=True):
        lbl = tk.Label(parent, text=text, font=FONT_S,
                       bg=parent.cget("bg"), fg=fg)
        if pack:
            lbl.pack(anchor=tk.W, pady=(4,1))
        return lbl

    def _entry(self, parent, show=None, state=tk.NORMAL):
        e = tk.Entry(parent, font=FONT_N, bg=ENTRY_BG, fg=TEXT,
                     insertbackground=TEXT, relief=tk.FLAT,
                     show=show or "", state=state,
                     disabledbackground=ENTRY_BG, disabledforeground=SUBTEXT)
        e.pack(fill=tk.X, pady=(0, 6), ipady=5)
        return e

    def _button(self, parent, text, command, width=20, pack=True):
        btn = tk.Button(parent, text=text, command=command,
                        font=FONT_B, bg=ACCENT, fg="white",
                        activebackground=ACCENT2, activeforeground="white",
                        relief=tk.FLAT, cursor="hand2", width=width, pady=6)
        if pack:
            btn.pack(pady=6, anchor=tk.W)
        return btn

    def _info_panel(self, parent, title, body):
        tk.Label(parent, text=title, font=FONT_B,
                 bg=PANEL, fg=ACCENT2).pack(anchor=tk.W, padx=10, pady=(12,4))
        tk.Label(parent, text=body, font=FONT_S,
                 bg=PANEL, fg=TEXT, justify=tk.LEFT, wraplength=300).pack(
                     anchor=tk.W, padx=10, pady=(0,10))

    def _set(self, label, text, color):
        label.config(text=text, fg=color)

    def _log(self, widget, text, color=TEXT):
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
