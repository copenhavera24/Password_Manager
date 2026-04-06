from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import json
import os
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PASSWORD_FILE = "passwords.json"
SALT_FILE = "salt.bin"

SESSION_KEY = None


def derive_key(password):
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
    )

    return kdf.derive(password.encode())


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation

    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))

        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password


def encrypt_json(data, key):
    aead = AESCCM(key)
    nonce = os.urandom(13)
    plaintext = json.dumps(data).encode()
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_json(ciphertext_with_nonce, key):
    try:
        aead = AESCCM(key)
        nonce = ciphertext_with_nonce[:13]
        ciphertext = ciphertext_with_nonce[13:]
        plaintext = aead.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted data.")
        return []


def save_password(site, username, password, description="", index=None):
    key = SESSION_KEY

    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "rb") as f:
            data = decrypt_json(f.read(), key)
    else:
        data = []

    entry = {
        "site": site,
        "username": username,
        "password": password,
        "description": description
    }

    if index is not None:
        data[index] = entry
    else:
        data.append(entry)

    with open(PASSWORD_FILE, "wb") as f:
        f.write(encrypt_json(data, key))


def delete_password(index):
    key = SESSION_KEY

    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "rb") as f:
            data = decrypt_json(f.read(), key)

        if 0 <= index < len(data):
            confirm = messagebox.askyesno("Confirm Delete", f"Delete password for {data[index]['site']}?")
            if confirm:
                data.pop(index)
                with open(PASSWORD_FILE, "wb") as f:
                    f.write(encrypt_json(data, key))
                load_main_ui("admin")


def load_passwords():
    key = SESSION_KEY

    if not os.path.exists(PASSWORD_FILE):
        return []

    with open(PASSWORD_FILE, "rb") as f:
        return decrypt_json(f.read(), key)


def create_entry_page(site="", username="", password="", description="", index=None):
    for widget in root.winfo_children():
        widget.destroy()

    ttk.Label(root, text="Password Entry", font=("Arial", 14)).pack(pady=10)

    ttk.Label(root, text="Website/App:").pack()
    site_entry = ttk.Entry(root)
    site_entry.pack(pady=5)
    site_entry.insert(0, site)

    ttk.Label(root, text="Username:").pack()
    user_entry = ttk.Entry(root)
    user_entry.pack(pady=5)
    user_entry.insert(0, username)

    ttk.Label(root, text="Password:").pack()
    pass_entry = ttk.Entry(root, show="*")
    pass_entry.pack(pady=5)
    pass_entry.insert(0, password)

    ttk.Label(root, text="Confirm Password:").pack()
    confirm_entry = ttk.Entry(root, show="*")
    confirm_entry.pack(pady=5)
    confirm_entry.insert(0, password)

    # 🔥 Show/Hide toggle
    show_password = False

    def toggle_password():
        nonlocal show_password
        show_password = not show_password

        if show_password:
            pass_entry.config(show="")
            confirm_entry.config(show="")
            toggle_btn.config(text="Hide Password")
        else:
            pass_entry.config(show="*")
            confirm_entry.config(show="*")
            toggle_btn.config(text="Show Password")

    # 🔥 Generator function
    def fill_generated_password():
        new_pass = generate_password()
        pass_entry.delete(0, END)
        confirm_entry.delete(0, END)
        pass_entry.insert(0, new_pass)
        confirm_entry.insert(0, new_pass)

    # Buttons (grouped nicely)
    btn_frame = ttk.Frame(root)
    btn_frame.pack(pady=5)

    ttk.Button(btn_frame, text="Generate Password", command=fill_generated_password).pack(side=LEFT, padx=5)
    toggle_btn = ttk.Button(btn_frame, text="Show Password", command=toggle_password)
    toggle_btn.pack(side=LEFT, padx=5)

    ttk.Label(root, text="Description (optional):").pack()
    desc_entry = ttk.Entry(root)
    desc_entry.pack(pady=5)
    desc_entry.insert(0, description)

    def on_save():
        s = site_entry.get()
        u = user_entry.get()
        p = pass_entry.get()
        cp = confirm_entry.get()
        d = desc_entry.get()

        if not s or not u or not p:
            messagebox.showerror("Error", "Site, username, and password are required!")
            return

        if p != cp:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        save_password(s, u, p, d, index)
        messagebox.showinfo("Saved", f"Password for {s} saved!")
        load_main_ui("admin")

    ttk.Button(root, text="Save", command=on_save).pack(pady=10)
    ttk.Button(root, text="Back", command=lambda: load_main_ui("admin")).pack(pady=5)


def load_main_ui(username):
    for widget in root.winfo_children():
        widget.destroy()

    top_frame = ttk.Frame(root)
    top_frame.pack(anchor="nw", fill="x")

    ttk.Button(top_frame, text="Save Password", command=lambda: create_entry_page()).pack(anchor="nw", padx=5, pady=5)

    ttk.Label(root, text=f"Welcome, {username}!", font=("Arial", 16)).pack(pady=10)

    passwords = load_passwords()

    display_frame = ttk.Frame(root)
    display_frame.pack(pady=10, padx=10, fill="x")

    for idx, entry in enumerate(passwords):
        row_frame = ttk.Frame(display_frame, padding=5)
        row_frame.pack(fill="x", pady=2)

        ttk.Label(row_frame, text=entry["site"], width=15, anchor="w").pack(side=LEFT, padx=5)
        ttk.Label(row_frame, text=entry["username"], width=15, anchor="w").pack(side=LEFT, padx=5)
        ttk.Label(row_frame, text=entry["password"], width=15, anchor="w").pack(side=LEFT, padx=5)
        ttk.Label(row_frame, text=entry.get("description", ""), width=20, anchor="w").pack(side=LEFT, padx=5)

        ttk.Button(row_frame, text="Edit", command=lambda i=idx: create_entry_page(
            passwords[i]["site"],
            passwords[i]["username"],
            passwords[i]["password"],
            passwords[i].get("description", ""),
            index=i
        )).pack(side=LEFT, padx=5)

        ttk.Button(row_frame, text="Delete", command=lambda i=idx: delete_password(i)).pack(side=LEFT, padx=5)

    ttk.Button(root, text="Quit", command=root.destroy).pack(pady=10)


def login():
    global SESSION_KEY

    username = username_entry.get()
    password = password_entry.get()

    if username == 'admin' and password == "1234":
        SESSION_KEY = derive_key(password)
        messagebox.showinfo("Login Successful", f"Welcome, {username}!")
        load_main_ui(username)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")


root = Tk(className="Login Form")

frm = ttk.Frame(root, padding=10)

ttk.Label(root, text="Username:").pack(pady=5)
username_entry = ttk.Entry(root)
username_entry.pack(pady=5)

ttk.Label(root, text="Password:").pack(pady=5)
password_entry = ttk.Entry(root, show="*")
password_entry.pack(pady=5)

ttk.Button(frm, text="Login", command=login).pack(side=LEFT, padx=5)
ttk.Button(frm, text="Quit", command=root.destroy).pack(side=LEFT, padx=5)

frm.pack()

root.mainloop()