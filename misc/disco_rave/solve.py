#!/usr/bin/env python3
# disco_rave_solution.py
import base64
import os
import re
import socket
import sys
from ast import literal_eval
from typing import List, Dict, Any, Tuple

import requests
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

REMOTE_HOST = "ctf.ac.upt.ro"
REMOTE_PORT = 9240  # <-- bon port

CHANNELS = [
    "1416908413375479891",
    "1417154025371209852",
]

PROXY_BASE = os.environ.get("PROXY_BASE", "https://proxy-gamma-steel-32.vercel.app/api/proxy")
PROXY_BOT_TOKEN = os.environ.get("PROXY_BOT_TOKEN")  # requis par le proxy pour éviter 401

DISCORD_EPOCH_MS = 1420070400000  # 2015-01-01T00:00:00.000Z


def fetch_encrypted_from_remote() -> str:
    with socket.create_connection((REMOTE_HOST, REMOTE_PORT), timeout=10) as s:
        f = s.makefile("rwb", buffering=0)
        line = f.readline().decode("utf-8", errors="replace").strip()
    # Parse {'encrypted': '...'} or {"encrypted":"..."}
    enc = None
    try:
        d = literal_eval(line)
        if isinstance(d, dict) and "encrypted" in d:
            enc = d["encrypted"]
    except Exception:
        pass
    if not enc:
        m = re.search(r"[\"']encrypted[\"']\s*:\s*[\"']([^\"']+)[\"']", line)
        if m:
            enc = m.group(1)
    if not enc:
        raise RuntimeError(f"Impossible d'extraire 'encrypted' depuis: {line}")
    return enc


def fetch_last_messages_via_proxy(channel_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    url = f"{PROXY_BASE}/channels/{channel_id}/messages?limit={limit}"
    headers = {}
    if PROXY_BOT_TOKEN:
        headers["Authorization"] = f"Bot {PROXY_BOT_TOKEN}"
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise RuntimeError(f"Réponse inattendue pour {channel_id}: pas une liste.")
    return data  # ordre: plus récent -> plus ancien


def aes_key_from_seed(seed: bytes) -> bytes:
    return SHA256.new(seed).digest()


def decrypt_flag(encrypted_b64: str, key32: bytes) -> str:
    raw = base64.b64decode(encrypted_b64)
    if len(raw) < 16:
        raise ValueError("Blob chiffré trop court (IV manquant).")
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key32, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")


def snowflake_to_timestamp_iso(snowflake: int) -> str:
    """
    Discord snowflake -> timestamp ISO8601 EXACT attendu par l'API messages:
    'YYYY-MM-DDTHH:MM:SS.mmmmmm+00:00'
    """
    ts_ms = (snowflake >> 22) + DISCORD_EPOCH_MS
    sec = ts_ms // 1000
    micros = (ts_ms % 1000) * 1000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=micros)
    # Discord renvoie généralement "+00:00" et 6 décimales
    return dt.isoformat(timespec="microseconds").replace("+00:00", "+00:00")


def build_seed_from_proxy() -> bytes:
    chunks: List[str] = []
    for cid in CHANNELS:
        for msg in fetch_last_messages_via_proxy(cid, 10):
            content = str(msg.get("content", ""))
            timestamp = str(msg.get("timestamp", ""))
            chunks.append(f"{content}{timestamp}")
    return "".join(chunks).encode("utf-8")


def ask_pairs_for_channel(cid: str) -> List[Tuple[str, str]]:
    print(f"\n== Channel {cid} ==")
    print("Colle 10 lignes au format:  content|message_id")
    print("(ordre: du PLUS RÉCENT au PLUS ANCIEN, tel qu'affiché dans Discord)")
    pairs = []
    for i in range(10):
        line = input().rstrip("\n")
        if "|" not in line:
            raise ValueError("Format attendu: content|message_id")
        content, mid = line.split("|", 1)
        pairs.append((content, mid))
    return pairs


def build_seed_from_snowflakes() -> bytes:
    """
    Entree utilisateur: pour CHAQUE channel, 10 lignes 'content|message_id'
    (ordre: plus récent -> plus ancien). On reconstruit timestamp depuis l'ID.
    """
    all_chunks: List[str] = []
    for cid in CHANNELS:
        pairs = ask_pairs_for_channel(cid)
        for content, mid in pairs:
            mid = mid.strip()
            if mid.startswith("http"):
                # supporte qu'on colle un lien du style https://discord.com/channels/guild/cid/mid
                mid = mid.rstrip("/").split("/")[-1]
            snow = int(mid)
            ts_iso = snowflake_to_timestamp_iso(snow)
            all_chunks.append(f"{content}{ts_iso}")
    return "".join(all_chunks).encode("utf-8")


def run_auto():
    print("[*] Connexion au service pour récupérer 'encrypted'…")
    enc = fetch_encrypted_from_remote()
    print("[*] Lecture via proxy (10 messages x 2)…")
    seed = build_seed_from_proxy()
    key = aes_key_from_seed(seed)
    print("[*] Déchiffrement…")
    flag = decrypt_flag(enc, key)
    print("\n✅ FLAG:", flag)
    if not re.fullmatch(r"CTF\{[0-9a-fA-F]{64}\}", flag):
        print("⚠️ Format attendu CTF{sha256}.")


def run_manual():
    print("\n=== MODE MANUAL (enc + proxy) ===")
    print("Colle la valeur 'encrypted' (Base64) puis Entrée:\n")
    enc = input().strip()
    print("[*] Lecture via proxy (10 messages x 2)…")
    seed = build_seed_from_proxy()
    key = aes_key_from_seed(seed)
    print("[*] Déchiffrement…")
    flag = decrypt_flag(enc, key)
    print("\n✅ FLAG:", flag)
    if not re.fullmatch(r"CTF\{[0-9a-fA-F]{64}\}", flag):
        print("⚠️ Format attendu CTF{sha256}.")


def run_snowflake():
    print("\n=== MODE SNOWFLAKE (100% manuel, SANS proxy) ===")
    print("Colle d'abord la valeur 'encrypted' (Base64) puis Entrée:\n")
    enc = input().strip()
    print("\nMaintenant, pour CHAQUE channel, colle 10 lignes: content|message_id")
    print("Astuce: clique droit sur ton message -> Copier le lien. L'ID est la 3e partie de l'URL.")
    print("IMPORTANT: coller dans l'ordre **PLus récent -> Plus ancien**.")
    seed = build_seed_from_snowflakes()
    key = aes_key_from_seed(seed)
    print("[*] Déchiffrement…")
    flag = decrypt_flag(enc, key)
    print("\n✅ FLAG:", flag)
    if not re.fullmatch(r"CTF\{[0-9a-fA-F]{64}\}", flag):
        print("⚠️ Format attendu CTF{sha256}.")


def main():
    mode = (sys.argv[1].lower() if len(sys.argv) > 1 else "snowflake")
    if mode == "auto":
        run_auto()
    elif mode == "manual":
        run_manual()
    elif mode in ("snowflake", "sf"):
        run_snowflake()
    else:
        print("Usage: python disco_rave_solution.py [snowflake|auto|manual]")
        sys.exit(1)


if __name__ == "__main__":
    main()
