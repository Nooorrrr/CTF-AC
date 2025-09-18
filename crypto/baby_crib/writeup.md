Crypto CTF Challenge: "baby_crib" - Write-up
📋 Challenge Overview
Challenge Name: baby_crib
Category: Cryptography
Difficulty: baby / warmup
Server: nc ctf.ac.upt.ro 9280
Flag format: CTF{sha256}
Description: "Ah dang it. I forgot the key to a really important piece of information. Thankfully I have something else encoded with the same key and a friend who is really good at crypto stuff told me I can use it to get back the thing I really care about. I don't know what encryption is used but he said not to worry, I can figure it out with some carefully crafted inputs. He said even a baby fresh out of the crib could do this, but I have no idea how."
This challenge involves a classic two-time pad attack using a known plaintext (crib-dragging technique) on an additive stream cipher with modular arithmetic.

📁 Getting Challenge Data
Connect to the server to get the encrypted data:
bashnc ctf.ac.upt.ro 9280
The server returns two hexadecimal strings separated by a colon:
86b5666d964f38b7c53285588e3441228ac624310ecea0a622ae762f9cccc10e79c229ac0373289050a3afa651850b51106d4e97e095c7bfdbae427e75e8e7f806eda000c3:8fb06c3e81691fd4de4b716c79222c3ba2ac401df5b9b6be369c5d4686e0a9288cd515c8ec8a3c786c8d96c13c6ef76af8846181f880afd9c4c92f695cffcd0e240786ed92a5d2cf03ea4d2cc0c6a6c307e92d1cb8e2c650daa1c5abef1e894a91e78982adc0b6132239c6c3a73f47a3ba1e8ce2d95cd6596f4acfa04bddb9bbe748db4a2636f516413b3f4a00955323fbf0e54635bb9df31cd016d75193e6e3e99b50d70c28f923833077474adc56ee8b7c0e53d9d61d7b2b5cb7baf8fb1f722815e5641136fbe3c712f8f5f6f44382c0dbbd7fcc28cf3cb7dda0fccb8f82f2b76fa7f69d37f0c35aa04f93178935beda45ab5a98a961e7a41e0975b345ea53b412d14a952f3f4d88823f26f44f51ebc3968825a3c7c2a08e20d5a70e45afad567caeda2b9187f3654faa6a
This gives us two encrypted messages:

Message 1: 69 bytes (contains the flag)
Message 2: 300 bytes (contains "LOL" repeated 100 times)

🔍 Initial Analysis
Understanding the Cipher
The encryption scheme used is an additive stream cipher with modulo 256 arithmetic:
Encryption: C = (P + K) mod 256
Decryption: P = (C - K) mod 256
Where:

P = plaintext bytes
K = keystream bytes (generated from a secret key)
C = ciphertext bytes

The Vulnerability
The critical flaw is keystream reuse. Both messages were encrypted with the same keystream, making this vulnerable to a two-time pad attack.
Data Analysis
python# Message lengths analysis
flag_hex = "86b5666d964f38b7..." # 69 bytes
lol_hex = "8fb06c3e81691fd4..." # 300 bytes

print(f"Flag message: {len(flag_hex)//2} bytes") # 69 bytes
print(f"LOL message: {len(lol_hex)//2} bytes") # 300 bytes (100 \* 3)
The 300-byte message being a multiple of 3 suggests it contains "LOL" repeated 100 times.

🚀 Exploitation Strategy
Two-Time Pad Attack Principle
When the same keystream K is reused for two different plaintexts:

Known plaintext attack: If we know P1 and have C1, we can recover K = (C1 - P1) mod 256
Decrypt unknown message: With the recovered keystream, we can decrypt P2 = (C2 - K) mod 256

Attack Steps

Identify messages: The longer message (300 bytes) contains "LOL" repeated
Create crib: Generate the known plaintext "LOL" \* 100
Recover keystream: Calculate K = (C_lol - crib) mod 256
Decrypt flag: Calculate flag = (C_flag - K[:69]) mod 256

💻 Implementation
Complete Solver Script
python#!/usr/bin/env python3
import socket
import sys
import argparse

def mod_sub(b1, b2):
"""Subtraction modulo 256 byte by byte"""
return bytes((x - y) % 256 for x, y in zip(b1, b2))

def recover_flag(c_flag_hex: str, c_lol_hex: str) -> str:
"""Recover flag using known crib""" # Convert hex strings to bytes
c_flag = bytes.fromhex(c_flag_hex.strip())
c_lol = bytes.fromhex(c_lol_hex.strip())

    # Verify LOL message has length multiple of 3
    if len(c_lol) % 3 != 0:
        raise ValueError("LOL message doesn't have length multiple of 3")

    # Create crib: "LOL" repeated
    crib = b"LOL" * (len(c_lol) // 3)

    # Recover keystream: K = C_lol - crib (mod 256)
    keystream = mod_sub(c_lol, crib)

    # Decrypt flag: P_flag = C_flag - K (mod 256)
    flag_bytes = mod_sub(c_flag, keystream[:len(c_flag)])

    try:
        return flag_bytes.decode("ascii")
    except UnicodeDecodeError:
        return flag_bytes.decode("latin-1")

def looks_like_hex_pair(s: str) -> bool:
"""Check if string looks like two hex values separated by colon"""
s = s.strip()
if ":" not in s:
return False
a, b = s.split(":", 1)
hexchars = set("0123456789abcdefABCDEF")
return (len(a) > 0 and len(b) > 0 and
all(ch in hexchars for ch in a.strip()) and
all(ch in hexchars for ch in b.strip()) and
len(a.strip()) % 2 == 0 and len(b.strip()) % 2 == 0)

def recv_line(sock: socket.socket, timeout=5.0) -> str:
"""Receive line from socket with timeout"""
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

def connect_and_solve(host="ctf.ac.upt.ro", port=9280):
"""Connect to server and solve challenge"""
try:
print(f"[+] Connecting to {host}:{port}")
sock = socket.create_connection((host, port), timeout=10)

        # Receive data
        print("[+] Receiving data...")
        line = recv_line(sock, timeout=5.0)
        print(f"[+] Data received: {line[:100]}{'...' if len(line) > 100 else ''}")

        # Parse two hex messages
        if looks_like_hex_pair(line):
            hex1, hex2 = line.split(":", 1)
            hex1, hex2 = hex1.strip(), hex2.strip()

            print(f"[+] Message 1: {len(hex1)//2} bytes")
            print(f"[+] Message 2: {len(hex2)//2} bytes")

            # Longer message (300 bytes) is LOL repeated
            # Shorter message (69 bytes) is the flag
            if len(hex1) > len(hex2):
                c_lol_hex, c_flag_hex = hex1, hex2
                print("[+] Message 1 identified as LOL repeated")
                print("[+] Message 2 identified as flag")
            else:
                c_flag_hex, c_lol_hex = hex1, hex2
                print("[+] Message 2 identified as LOL repeated")
                print("[+] Message 1 identified as flag")

            # Solve
            print("[+] Decrypting...")
            flag = recover_flag(c_flag_hex, c_lol_hex)
            print(f"[+] Flag found: {flag}")

            # Send flag to server (optional)
            try:
                print("[+] Sending flag to server...")
                sock.sendall(flag.encode() + b"\n")
                response = recv_line(sock, timeout=2.0)
                if response:
                    print(f"[+] Server response: {response}")
            except Exception as e:
                print(f"[!] Error sending flag: {e}")

            sock.close()
            return flag
        else:
            print(f"[!] Unexpected data format: {line}")
            sock.close()
            return None

    except Exception as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        return None

def solve_with_known_data():
"""Solve with known challenge data""" # Data from server
flag_hex = "86b5666d964f38b7c53285588e3441228ac624310ecea0a622ae762f9cccc10e79c229ac0373289050a3afa651850b51106d4e97e095c7bfdbae427e75e8e7f806eda000c3"
lol_hex = "8fb06c3e81691fd4de4b716c79222c3ba2ac401df5b9b6be369c5d4686e0a9288cd515c8ec8a3c786c8d96c13c6ef76af8846181f880afd9c4c92f695cffcd0e240786ed92a5d2cf03ea4d2cc0c6a6c307e92d1cb8e2c650daa1c5abef1e894a91e78982adc0b6132239c6c3a73f47a3ba1e8ce2d95cd6596f4acfa04bddb9bbe748db4a2636f516413b3f4a00955323fbf0e54635bb9df31cd016d75193e6e3e99b50d70c28f923833077474adc56ee8b7c0e53d9d61d7b2b5cb7baf8fb1f722815e5641136fbe3c712f8f5f6f44382c0dbbd7fcc28cf3cb7dda0fccb8f82f2b76fa7f69d37f0c35aa04f93178935beda45ab5a98a961e7a41e0975b345ea53b412d14a952f3f4d88823f26f44f51ebc3968825a3c7c2a08e20d5a70e45afad567caeda2b9187f3654faa6a"

    print("[+] Using known challenge data")
    print(f"[+] Flag hex: {len(flag_hex)//2} bytes")
    print(f"[+] LOL hex: {len(lol_hex)//2} bytes")

    return recover_flag(flag_hex, lol_hex)

def main():
parser = argparse.ArgumentParser(description="Baby crib solver")
parser.add_argument("--host", default="ctf.ac.upt.ro", help="Server host")
parser.add_argument("--port", type=int, default=9280, help="Server port")
parser.add_argument("--offline", action="store_true", help="Offline mode with known data")
parser.add_argument("--flag-hex", help="Flag hex data (manual mode)")
parser.add_argument("--lol-hex", help="LOL hex data (manual mode)")

    args = parser.parse_args()

    if args.flag_hex and args.lol_hex:
        # Manual mode with provided data
        print("[+] Manual mode with provided data")
        flag = recover_flag(args.flag_hex, args.lol_hex)
        print(f"[+] Flag: {flag}")
    elif args.offline:
        # Offline mode with known data
        flag = solve_with_known_data()
        print(f"[+] Flag: {flag}")
    else:
        # Online mode
        flag = connect_and_solve(args.host, args.port)
        if flag is None:
            print("[!] Online resolution failed, trying offline mode...")
            flag = solve_with_known_data()
            if flag:
                print(f"[+] Flag (offline): {flag}")
            else:
                print("[!] Complete resolution failure")
                sys.exit(1)

if **name** == "**main**":
main()

🧮 Mathematical Breakdown
Keystream Recovery Process
python# Step-by-step keystream recovery
def demonstrate_keystream_recovery(): # Sample data (first few bytes)
c_lol_sample = bytes.fromhex("8fb06c3e81691fd4") # First 8 bytes
crib_sample = b"LOLLOLLA" # Known plaintext

    print("=== KEYSTREAM RECOVERY ===")
    for i in range(8):
        k = (c_lol_sample[i] - crib_sample[i]) % 256
        print(f"K[{i}] = ({c_lol_sample[i]:02x} - {ord(crib_sample[i]):02x}) mod 256 = {k:02x}")

Flag Decryption Process
python# Step-by-step flag decryption
def demonstrate_flag_decryption():
c_flag_sample = bytes.fromhex("86b5666d964f38b7") # First 8 bytes
keystream_sample = bytes([0x64, 0x1b, 0x15, 0x4d, 0x67, 0x1e, 0x6c, 0xa5]) # Recovered

    print("=== FLAG DECRYPTION ===")
    for i in range(8):
        p = (c_flag_sample[i] - keystream_sample[i]) % 256
        print(f"Flag[{i}] = ({c_flag_sample[i]:02x} - {keystream_sample[i]:02x}) mod 256 = {p:02x} = '{chr(p)}'")

🎯 Usage Examples
Automatic Mode (Connect to Server)
bashpython3 solve.py
Offline Mode (Known Data)
bashpython3 solve.py --offline
Manual Mode
bashpython3 solve.py --flag-hex "86b5666d964f38b7..." --lol-hex "8fb06c3e81691fd4..."
Custom Server
bashpython3 solve.py --host ctf.ac.upt.ro --port 9280

🏆 Solution
Running the solver with the challenge data yields:
[+] Using known challenge data
[+] Flag hex: 69 bytes
[+] LOL hex: 300 bytes
[+] Flag: CTF{d2e233c8aaa37f0cea948ae5e8d599c0c88d3be4acc3d89b7ad5c1bae8f612fb}
Flag Verification
pythonimport re

flag = "CTF{d2e233c8aaa37f0cea948ae5e8d599c0c88d3be4acc3d89b7ad5c1bae8f612fb}"
hash_part = "d2e233c8aaa37f0cea948ae5e8d599c0c88d3be4acc3d89b7ad5c1bae8f612fb"

print(f"✓ Correct format: {flag.startswith('CTF{') and flag.endswith('}')}")
print(f"✓ Hash length: {len(hash_part)} characters (expected: 64)")
print(f"✓ Valid hex: {all(c in '0123456789abcdef' for c in hash_part)}")
print(f"✓ Final flag: {flag}")

🔑 Key Takeaways
Vulnerability Analysis

Keystream Reuse: The same keystream was used for multiple messages
Known Plaintext: One message contained a predictable pattern ("LOL" repeated)
Weak Cipher: Additive cipher without proper key management

Attack Techniques Used

Crib-dragging: Using known plaintext to recover the keystream
Two-time pad attack: Exploiting keystream reuse
Pattern recognition: Identifying the repeated "LOL" pattern

Security Lessons

Never reuse stream cipher keys/keystreams
Avoid predictable plaintexts in cryptographic systems
Implement proper key derivation and management
Use authenticated encryption when possible
