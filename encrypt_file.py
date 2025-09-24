import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from secure_log import log_encrypt, password_fingerprint

MAGIC = b"PYA1"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    orig_name = os.path.basename(path).encode("utf-8")
    name_len = len(orig_name).to_bytes(2, "big")
    aad = MAGIC + name_len + orig_name
    ct = aes.encrypt(nonce, data, aad)
    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(MAGIC + salt + nonce + name_len + orig_name + ct)
    os.remove(path)  
    return out_path

if __name__ == "__main__":
    root = tk.Tk(); root.withdraw()
    path = filedialog.askopenfilename(title="Selecciona un archivo para CIFRAR")
    if not path:
        messagebox.showinfo("Cifrado", "No se seleccionó archivo."); exit(0)
    pwd = simpledialog.askstring("Contraseña", "Introduce la contraseña:", show="*")
    if not pwd:
        messagebox.showerror("Cifrado", "No se introdujo contraseña."); exit(1)
    pwd_fp = password_fingerprint(pwd)
    try:
        out = encrypt_file(path, pwd)
        log_encrypt(path, out, ok=True, pwd_fp=pwd_fp)
        messagebox.showinfo("Cifrado", f"Archivo cifrado y original borrado.\n{out}")
    except Exception as e:
        log_encrypt(path, "", ok=False, pwd_fp=pwd_fp, note=str(e))
        messagebox.showerror("Cifrado", f"Error: {e}")
