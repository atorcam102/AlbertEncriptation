# secure_log.py
import os, json, time, hashlib, hmac
from pathlib import Path
import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_ID = "pyenc.log.v1"
KEY_NAME = "enc_log_key"
LOG_DIR = Path.home() / ".pyenc"
LOG_FILE = LOG_DIR / "log.enc"
AAD = b"PYENC-LOG-v1"

def _ensure_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def _get_or_create_log_key() -> bytes:
    key = keyring.get_password(APP_ID, KEY_NAME)
    if key is None:
        new_key = os.urandom(32)
        keyring.set_password(APP_ID, KEY_NAME, new_key.hex())
        return new_key
    return bytes.fromhex(key)

def _encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, AAD)
    return nonce + ct

def _decrypt_blob(key: bytes, blob: bytes) -> bytes:
    aes = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aes.decrypt(nonce, ct, AAD)

def _load_log_jsonl(key: bytes) -> list[dict]:
    if not LOG_FILE.exists():
        return []
    data = _decrypt_blob(key, LOG_FILE.read_bytes())
    lines = [ln for ln in data.decode("utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]

def _save_log_jsonl(key: bytes, entries: list[dict]) -> None:
    txt = "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n"
    blob = _encrypt_blob(key, txt.encode("utf-8"))
    LOG_FILE.write_bytes(blob)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def password_fingerprint(password: str) -> str:
    """Devuelve una huella no reversible para identificar contraseñas."""
    key = _get_or_create_log_key()
    tag = hmac.new(key, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return tag[:12]

def log_encrypt(original_path: str, encrypted_path: str, ok: bool, pwd_fp: str = "", note: str = "") -> None:
    _ensure_dirs()
    key = _get_or_create_log_key()
    entries = _load_log_jsonl(key)
    ts = int(time.time())
    entry = {
        "ts": ts,
        "op": "ENCRYPT",
        "original": os.path.abspath(original_path),
        "encrypted": os.path.abspath(encrypted_path) if encrypted_path else None,
        "ok": bool(ok),
        "pwd_fp": pwd_fp,
        "note": note or "",
    }
    try:
        if encrypted_path and os.path.exists(encrypted_path):
            entry["enc_sha256"] = sha256_file(encrypted_path)
    except Exception:
        entry["enc_sha256"] = None
    entries.append(entry)
    _save_log_jsonl(key, entries)

def log_decrypt(encrypted_path: str, restored_path: str, ok: bool, pwd_fp: str = "", note: str = "") -> None:
    _ensure_dirs()
    key = _get_or_create_log_key()
    entries = _load_log_jsonl(key)
    ts = int(time.time())
    entry = {
        "ts": ts,
        "op": "DECRYPT",
        "encrypted": os.path.abspath(encrypted_path),
        "restored": os.path.abspath(restored_path) if restored_path else None,
        "ok": bool(ok),
        "pwd_fp": pwd_fp,
        "note": note or "",
    }
    try:
        if os.path.exists(encrypted_path):
            entry["enc_sha256"] = sha256_file(encrypted_path)
    except Exception:
        entry["enc_sha256"] = None
    entries.append(entry)
    _save_log_jsonl(key, entries)

def read_log() -> list[dict]:
    _ensure_dirs()
    key = _get_or_create_log_key()
    return _load_log_jsonl(key)
