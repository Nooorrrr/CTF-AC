#!/usr/bin/env python3
"""
solve_pythonese_final.py

Final solver for the "Pythonese" .pyc challenge.

Usage:
    python solve_pythonese_final.py bytecode.pyc

Behavior:
 - Try to build and call f13 in-process (fast, but may fail if the code object uses unavailable globals
   or contains unsupported bytecode sequences).
 - If that fails, perform a static-only solve:
    * extract integer/byte sequences from f13.co_consts
    * search k1,k2 in 0..255 with printable heuristics
    * for promising keys try permutations+reversal to match 'ctf{[0-9a-f]{64}}'
 - Print the flag when found.
"""
from __future__ import annotations
import sys
import marshal
import types
import dis
import itertools
import re
import time
from typing import Sequence, List, Tuple

PYC_HEADER_SIZE = 16
FLAG_RE = re.compile(r'ctf\{[0-9a-f]{64}\}', re.I)

def load_pyc_codeobj(path: str) -> types.CodeType:
    with open(path, "rb") as f:
        data = f.read()
    return marshal.loads(data[PYC_HEADER_SIZE:])

def find_codeobj_by_name(root: types.CodeType, name: str):
    stack = [root]
    seen = set()
    while stack:
        c = stack.pop()
        if id(c) in seen:
            continue
        seen.add(id(c))
        if getattr(c, "co_name", None) == name:
            return c
        for const in c.co_consts:
            if isinstance(const, types.CodeType):
                stack.append(const)
    return None

def build_function_from_code(codeobj: types.CodeType):
    # minimal globals
    globs = {}
    return types.FunctionType(codeobj, globs, name=codeobj.co_name)

def extract_int_sequences(code: types.CodeType) -> List[Tuple[int, ...]]:
    found = []
    def walk(cobj: types.CodeType):
        for const in cobj.co_consts:
            if isinstance(const, (tuple, list)) and len(const) >= 4 and all(isinstance(x, int) for x in const):
                found.append(tuple(const))
            elif isinstance(const, (bytes, bytearray)) and len(const) >= 4:
                found.append(tuple(b for b in const))
            elif isinstance(const, types.CodeType):
                walk(const)
    walk(code)
    # deduplicate preserving order
    uniq = []
    seen = set()
    for s in found:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq

def fvdy_transform(chunk: Sequence[int], k1: int, k2: int) -> bytes:
    kk = k1 & 0xff
    out = bytearray()
    for v in chunk:
        b = (((v >> 1) - k2) ^ kk) & 0xff
        out.append(b)
    return bytes(out)

def printable_ratio(b: bytes) -> float:
    if not b: return 0.0
    good = sum(32 <= x < 127 for x in b)
    return good / len(b)

def try_permutations_for_flag(decoded_chunks: List[bytes], max_attempts: int = 2_000_000):
    n = len(decoded_chunks)
    variants = [(c, c[::-1]) for c in decoded_chunks]
    attempts = 0
    if n <= 8:
        for perm in itertools.permutations(range(n)):
            perm_pairs = [variants[i] for i in perm]
            for mask in range(1 << n):
                parts = [perm_pairs[i][(mask >> i) & 1] for i in range(n)]
                candidate = b"".join(parts)
                attempts += 1
                if attempts % 200000 == 0:
                    print(f"  [*] tried {attempts} concatenations...")
                s = candidate.decode('utf-8', errors='ignore')
                m = FLAG_RE.search(s)
                if m:
                    return m.group(0)
                if attempts >= max_attempts:
                    return None
        return None
    else:
        # heuristic: try permutations of largest 8 chunks
        idxs = sorted(range(n), key=lambda i: -len(decoded_chunks[i]))[:8]
        sub = [decoded_chunks[i] for i in idxs]
        print("[*] many chunks (>8), trying heuristic subset (largest 8)")
        return try_permutations_for_flag(sub, max_attempts=max_attempts)

def static_solve(f13_code: types.CodeType):
    seqs = extract_int_sequences(f13_code)
    if not seqs:
        print("[!] No candidate integer/byte sequences found in f13.")
        return None

    print(f"[*] {len(seqs)} candidate sequences extracted; lengths: {[len(s) for s in seqs]}")

    # fast path: check if any sequence decodes directly with common keys (from writeup)
    # but we won't rely solely on that. We'll search k1,k2.
    start = time.time()
    checked = 0
    for k1 in range(256):
        for k2 in range(256):
            checked += 1
            # decode all chunks
            decoded = [fvdy_transform(s, k1, k2) for s in seqs]
            ratios = [printable_ratio(d) for d in decoded]
            # pruning heuristics: at least half chunks > 0.6 printable OR avg > 0.5
            good = sum(1 for r in ratios if r > 0.6)
            avg = sum(ratios)/len(ratios)
            if good < max(1, len(seqs)//2) and avg < 0.5:
                continue
            # candidate — try permutations
            print(f"[+] candidate keys k1={k1} k2={k2} printable_ratios={[f'{r:.2f}' for r in ratios]}")
            flag = try_permutations_for_flag(decoded, max_attempts=500_000)
            if flag:
                print(f"[*] keys found after testing {checked} pairs in {time.time()-start:.1f}s")
                return {"k1": k1, "k2": k2, "flag": flag, "decoded": decoded}
        if k1 % 32 == 0:
            elapsed = time.time() - start
            print(f"  progress: k1={k1} checked pairs={checked} elapsed={elapsed:.1f}s")
    print("[!] static search exhausted — no flag found")
    return None

def main(pyc_path: str):
    try:
        root_code = load_pyc_codeobj(pyc_path)
    except Exception as e:
        print("[!] Failed to load .pyc:", e)
        return 1

    f13 = find_codeobj_by_name(root_code, "f13")
    if f13 is None:
        print("[!] f13 not found in code object constants.")
        return 2

    # 1) Try in-process execution of f13 (fast) — may fail with unknown opcode or missing globals
    try:
        print("[*] Attempting to construct and call f13 in-process (fast)...")
        f13_func = build_function_from_code(f13)
        try:
            out = f13_func(81, 173)
            if isinstance(out, str) and FLAG_RE.search(out):
                print("[+] Flag (in-process):", out)
                return 0
            # else print and continue to static
            print("[*] In-process call returned (no flag):", repr(out)[:200])
        except Exception as e:
            print("[!] In-process call failed:", e)
    except Exception as e:
        print("[!] Building in-process function failed:", e)

    # 2) Static solve
    print("[*] Falling back to static analysis search (no exec)...")
    result = static_solve(f13)
    if result:
        print("[+] Flag (static):", result["flag"])
        print("[+] Keys: k1={}, k2={}".format(result["k1"], result["k2"]))
        # optionally print decoded chunk hexes
        for i, d in enumerate(result["decoded"]):
            print(f" CHUNK_{i} = {d.hex()}  len={len(d)} printable={printable_ratio(d):.2f}")
        return 0
    else:
        print("[!] Could not recover flag with static strategy.")
        return 3

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python solve_pythonese_final.py bytecode.pyc")
        sys.exit(2)
    sys.exit(main(sys.argv[1]) or 0)
