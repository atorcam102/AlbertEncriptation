import os, sys, tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from totp_helper import get_or_create_totp_secret, provisioning_uri, verify_totp

MAGIC = b"PYA1"  

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode("utf-8"))

def safe_restore_path(dirpath: str, orig_name: str) -> str:
    dest = os.path.join(dirpath, orig_name)
    if not os.path.exists(dest):
        return dest
    base, ext = os.path.splitext(orig_name)
    i = 1
    while True:
        candidate = os.path.join(dirpath, f"{base} (restored {i}){ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1

def decrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        blob = f.read()

    if len(blob) < 4+16+12+2:
        raise ValueError("Archivo demasiado corto o corrupto.")

    magic = blob[:4]
    if magic != MAGIC:
        raise ValueError("Formato no reconocido (MAGIC inválido).")

    salt  = blob[4:20]
    nonce = blob[20:32]
    name_len = int.from_bytes(blob[32:34], "big")
    if 34 + name_len > len(blob):
        raise ValueError("Cabecera corrupta (longitud de nombre).")

    orig_name = blob[34:34+name_len].decode("utf-8", errors="strict")
    ct = blob[34+name_len:]

    key = derive_key(password, salt)
    aes = AESGCM(key)
    aad = MAGIC + blob[32:34] + blob[34:34+name_len]
    data = aes.decrypt(nonce, ct, aad)

    out_path = safe_restore_path(os.path.dirname(path), orig_name)
    with open(out_path, "wb") as f:
        f.write(data)

    os.remove(path) 
    return out_path

def pick_enc_from_args_or_dialog() -> str:
  
    for a in sys.argv[1:]:
        if a.lower().endswith(".enc") and os.path.exists(a):
            return a
    
    return filedialog.askopenfilename(
        title="Selecciona un archivo .enc para DESCIFRAR",
        filetypes=[("Archivos cifrados", "*.enc"), ("Todos los archivos", "*.*")]
    )

if __name__ == "__main__":
    root = tk.Tk(); root.withdraw()


    first_secret = get_or_create_totp_secret()  
    
    uri = provisioning_uri(account_name="TuMac", issuer="PyEnc")

    

    enc_path = pick_enc_from_args_or_dialog()
    if not enc_path:
        messagebox.showinfo("Descifrado", "No se seleccionó archivo."); sys.exit(0)

    pwd = simpledialog.askstring("Contraseña", f"Contraseña para:\n{os.path.basename(enc_path)}", show="*")
    if not pwd:
        messagebox.showerror("Descifrado", "No se introdujo contraseña."); sys.exit(1)

    code = simpledialog.askstring("Código TOTP", "Introduce el código de 6 dígitos del iPhone:", show="*")
    if not code or not verify_totp(code):
        messagebox.showerror("Segundo factor", "Código TOTP inválido o caducado."); sys.exit(1)

    try:
        out = decrypt_file(enc_path, pwd)
        messagebox.showinfo("Descifrado", f"Archivo restaurado y .enc borrado.\n{out}")
    except Exception as e:
        messagebox.showerror("Descifrado", f"Error: {e}")
