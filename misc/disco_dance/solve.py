#!/usr/bin/env python3
import base64
import json
import re
import socket
import sys
from ast import literal_eval
from typing import List, Optional

import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

# --- Paramètres du challenge (tu peux ajuster si besoin) ---
REMOTE_HOST = "ctf.ac.upt.ro"
REMOTE_PORT = 9090
# Proxy public utilisé par le serveur pour lire les 5 derniers messages du channel
PROXY_URL = "https://proxy-gamma-steel-32.vercel.app/api/proxy/channels/1416908413375479891/messages?limit=5"
# ------------------------------------------------------------

def fetch_encrypted_from_remote(host: str, port: int) -> str:
    """Récupère la ligne du service et extrait le champ 'encrypted'."""
    with socket.create_connection((host, port), timeout=10) as s:
        s_file = s.makefile("rwb", buffering=0)
        # Lire une ligne (le service envoie un dict Python sous forme de str)
        line = s_file.readline().decode("utf-8", errors="replace").strip()
    # Exemple: {'encrypted': 'BASE64...'}
    # On parse de façon robuste avec literal_eval, puis fallback regex si besoin
    encrypted = None
    try:
        d = literal_eval(line)
        if isinstance(d, dict) and "encrypted" in d:
            encrypted = d["encrypted"]
    except Exception:
        m = re.search(r"'encrypted'\s*:\s*'([^']+)'", line)
        if m:
            encrypted = m.group(1)
    if not encrypted:
        raise RuntimeError(f"Impossible d'extraire 'encrypted' depuis: {line}")
    return encrypted

def fetch_last_5_messages(url: str) -> List[str]:
    """Récupère les 5 derniers messages (dans l'ordre renvoyé par l'API)."""
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise RuntimeError("Réponse proxy inattendue (pas une liste).")
    msgs = [str(item.get("content", "")) for item in data]
    if len(msgs) < 5:
        raise RuntimeError(f"Moins de 5 messages reçus: {len(msgs)}")
    return msgs[:5]

def derive_key_from_messages(messages: List[str]) -> bytes:
    """Concatène les contenus puis SHA256 -> clé AES (32 octets)."""
    concatenated = "".join(messages).encode("utf-8")
    digest = SHA256.new(concatenated).digest()
    return digest

def decrypt_flag(encrypted_b64: str, key32: bytes) -> str:
    """Déchiffre Base64( IV || CIPHERTEXT ) en AES-CBC, PKCS#7."""
    raw = base64.b64decode(encrypted_b64)
    if len(raw) < 16:
        raise ValueError("Blob chiffré trop court (pas d'IV).")
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key32, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8", errors="strict")

def manual_input() -> (str, List[str]):
    print("\n=== MODE MANUEL ===")
    print("Colle la valeur 'encrypted' (Base64) reçue du service puis Entrée:\n")
    encrypted = input().strip()
    print("\nColle les 5 derniers messages du channel, **dans l'ordre renvoyé par l'API**.")
    print("Colle chaque message, puis appuie Entrée (5 fois):\n")
    messages = []
    for i in range(5):
        messages.append(input())
    return encrypted, messages

def pretty_preview(messages: List[str]) -> None:
    print("\n--- Aperçu des 5 messages concaténés ---")
    for i, m in enumerate(messages, 1):
        print(f"[{i}] {m}")
    print("----------------------------------------")

def main(argv: List[str]) -> None:
    mode = (argv[1].lower() if len(argv) > 1 else "auto")
    if mode not in ("auto", "manual"):
        print("Usage: python disco_dance.py [auto|manual]")
        sys.exit(1)

    if mode == "auto":
        print("[*] Récupération de 'encrypted' depuis le service…")
        encrypted = fetch_encrypted_from_remote(REMOTE_HOST, REMOTE_PORT)
        print("[*] Récupération des 5 derniers messages via le proxy…")
        messages = fetch_last_5_messages(PROXY_URL)
        pretty_preview(messages)
    else:
        encrypted, messages = manual_input()

    print("[*] Dérivation de la clé (SHA256 des 5 messages concaténés)…")
    key32 = derive_key_from_messages(messages)

    print("[*] Déchiffrement AES-CBC…")
    flag = decrypt_flag(encrypted, key32)

    print("\n✅ FLAG :", flag)
    # Si tu veux être strict sur le format :
    if not re.fullmatch(r"ctf\{[0-9a-fA-F]{64}\}", flag) and not re.fullmatch(r"CTF\{[0-9a-fA-F]{64}\}", flag):
        print("⚠️ Avertissement : le format attendu ressemble à ctf{sha256}. Vérifie la casse exigée par l’énoncé.")

if __name__ == "__main__":
    main(sys.argv)