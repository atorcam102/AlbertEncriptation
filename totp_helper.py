# totp_helper.py
import os
import keyring
import pyotp

APP_ID = "pyenc.totp.v1"
KEY_NAME = "totp_secret"  # se guarda en el Llavero de macOS

def get_or_create_totp_secret() -> str:
    secret = keyring.get_password(APP_ID, KEY_NAME)
    if secret:
        return secret
    # Genera secreto base32 compatible con Authenticator
    secret = pyotp.random_base32()  # 160 bits
    keyring.set_password(APP_ID, KEY_NAME, secret)
    return secret

def provisioning_uri(account_name: str = "Usuario", issuer: str = "PyEnc") -> str:
    secret = get_or_create_totp_secret()
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)

def verify_totp(code: str) -> bool:
    secret = get_or_create_totp_secret()
    totp = pyotp.TOTP(secret)
    # ventana de tolerancia ±1 paso (30s) para relojes ligeramente desincronizados
    try:
        code = code.strip().replace(" ", "")
    except Exception:
        pass
    return bool(code) and totp.verify(code, valid_window=1)