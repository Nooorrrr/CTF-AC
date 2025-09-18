# baby_crib (Crypto) — Write-up

> **Catégorie :** Cryptographie  
> **Difficulté :** baby / warmup  
> **Remote :** `nc ctf.ac.upt.ro 9280`  
> **Flag format :** `CTF{sha256}`

---

## TL;DR

Deux messages ont été chiffrés avec **le même keystream** via un chiffrement **additif octet-par-octet modulo 256** (un “Vigenère sur octets”).  
On connaît le plaintext de l’un d’eux (une longue chaîne `"LOLLOLLOL..."`), donc on récupère le **keystream** puis on **décrypte** l’autre (le flag).

**Flag final :**
