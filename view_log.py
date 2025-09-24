# view_log.py
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from secure_log import read_log

def format_ts(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Log de cifrados (protegido por Llavero)")

    try:
        entries = read_log()   # <- aquí macOS puede pedir Touch ID/contraseña
    except Exception as e:
        messagebox.showerror("Log", f"No se pudo abrir el log:\n{e}")
        root.destroy()
        raise SystemExit(1)

    txt = scrolledtext.ScrolledText(root, width=100, height=30)
    txt.pack(padx=10, pady=10)

    if not entries:
        txt.insert("1.0", "No hay entradas en el log.")
    else:
        lines = []
        for e in entries:
            line = [
                f"[{format_ts(e.get('ts', 0))}] {e.get('op','?')}",
                f"  ok={e.get('ok')}",
            ]
            if e.get("op") == "ENCRYPT":
                line.append(f"  original={e.get('original')}")
                line.append(f"  encrypted={e.get('encrypted')}")
            elif e.get("op") == "DECRYPT":
                line.append(f"  encrypted={e.get('encrypted')}")
                line.append(f"  restored={e.get('restored')}")
            if e.get("enc_sha256"):
                line.append(f"  enc_sha256={e['enc_sha256'][:16]}…")
            if e.get("note"):
                line.append(f"  note={e['note']}")
            lines.append("\n".join(line))
        txt.insert("1.0", "\n\n".join(lines))

    root.mainloop()
