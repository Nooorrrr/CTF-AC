#!/usr/bin/env python3
import argparse
import socket
import sys

def mod_sub(b1, b2):
    return bytes((x - y) % 256 for x, y in zip(b1, b2))

def recover_flag(c_flag_hex: str, c_lol_hex: str) -> str:
    c_flag = bytes.fromhex(c_flag_hex.strip())
    c_lol  = bytes.fromhex(c_lol_hex.strip())

    # plaintext connu = "LOL" répété
    if len(c_lol) % 3 != 0:
        raise ValueError("lol.hex n'a pas une longueur multiple de 3 (LOL répété)")
    crib = (b"LOL" * (len(c_lol)//3))

    # Keystream K = C_lol - crib (mod 256)
    K = mod_sub(c_lol, crib)

    # Decrypt flag = C_flag - K (mod 256)
    p_flag = mod_sub(c_flag, K[:len(c_flag)])

    try:
        return p_flag.decode("ascii")
    except UnicodeDecodeError:
        # Au cas très improbable où il y aurait des octets hors ASCII
        return p_flag.decode("latin1")

def looks_like_hex_pair(s: str) -> bool:
    s = s.strip()
    if ":" not in s:
        return False
    a, b = s.split(":", 1)
    hexchars = set("0123456789abcdefABCDEF")
    return (len(a) > 0 and len(b) > 0 and
            all(ch in hexchars for ch in a.strip()) and
            all(ch in hexchars for ch in b.strip()) and
            len(a.strip()) % 2 == 0 and len(b.strip()) % 2 == 0)

def recv_line(sock: socket.socket, timeout=2.0) -> str:
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data or b"\r" in data:
                break
    except socket.timeout:
        pass
    return data.decode(errors="ignore").strip()

def main():
    parser = argparse.ArgumentParser(description="Baby crib solver")
    parser.add_argument("--host", default="ctf.ac.upt.ro")
    parser.add_argument("--port", type=int, default=9280)
    parser.add_argument("--flag-file", default="flag.hex", help="fallback local file")
    parser.add_argument("--lol-file", default="lol.hex", help="fallback local file")
    parser.add_argument("--no-net", action="store_true", help="ne pas se connecter; mode offline pur")
    args = parser.parse_args()

    c_flag_hex = c_lol_hex = None
    sock = None

    if not args.no_net:
        try:
            sock = socket.create_connection((args.host, args.port), timeout=5)
            line = recv_line(sock, timeout=2.0)
            if looks_like_hex_pair(line):
                a, b = line.split(":", 1)
                # on suppose que le plus court est le flag (69 octets dans l'énoncé)
                if len(a.strip()) <= len(b.strip()):
                    c_flag_hex, c_lol_hex = a.strip(), b.strip()
                else:
                    c_flag_hex, c_lol_hex = b.strip(), a.strip()
            # Sinon, on tombera sur le mode fichiers ci-dessous
        except Exception as e:
            print(f"[!] Connexion échouée ({e}), bascule en mode fichiers.", file=sys.stderr)

    if c_flag_hex is None or c_lol_hex is None:
        # Mode offline depuis les fichiers
        try:
            with open(args.flag_file, "r") as f:
                c_flag_hex = f.read().strip()
            with open(args.lol_file, "r") as f:
                c_lol_hex = f.read().strip()
        except Exception as e:
            print(f"[!] Impossible de lire {args.flag_file} / {args.lol_file}: {e}", file=sys.stderr)
            sys.exit(1)

    flag = recover_flag(c_flag_hex, c_lol_hex)
    print(flag)

    # Optionnel: renvoyer le flag au service si on est connecté et que ça peut valider
    if sock:
        try:
            sock.sendall(flag.encode() + b"\n")
            resp = recv_line(sock, timeout=2.0)
            if resp:
                print(resp)
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
