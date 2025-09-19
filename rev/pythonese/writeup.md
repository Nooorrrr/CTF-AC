Pythonese — full write-up (reverse-engineering .pyc)
0) TL;DR

The program is a compiled Python bytecode (.pyc) with several layers of “noise” (anti-debug checks, async detours, weird decompiler output).

With any random input, it prints a URL-safe Base64 string derived from input (a red herring).

The real flag is hard-wired in a function named f13, revealed when a secret SHA-256 check passes. we don’t need that secret; we can recover the flag directly from f13.

Flag: ctf{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}

1) First run — what you see

When I ran the bytecode directly:

PS C:\Users\DELL\OneDrive\Desktop\New folder> py -3.11 .\bytecode.pyc
-7-cWrPc3AqGqTGMiJb0r8FxJnfQgjMjZoEPMFmD2uo
VL8rNxZaqcOHehbEjd6to9P9_6qij8Y6KBjFgusGBj0
PS C:\Users\DELL\OneDrive\Desktop\New folder>


It printed two lines of Base64-ish text (URL-safe characters, no = padding).

It didn’t ask me anything — it just exited.

Takeaway: the program can produce “legit-looking” outputs even with no useful input. So we need to look inside.

2) Quick black-box probe (your harness)

You also tried a small harness:

PS C:\> py -3.11 solve_pythonese_deep.py "test_input"
[input]    'test_input'
[index j]  2
[pyc out]  -7-cWrPc3AqGqTGMiJb0r8FxJnfQgjMjZoEPMFmD2uo
[result]   -7-cWrPc3AqGqTGMiJb0r8FxJnfQgjMjZoEPMFmD2uo
[verify]   inner run(...) == outer f14(input) ? True


For test_input, both the “outer” and the “inner” path print the same string:

-7-cWrPc3AqGqTGMiJb0r8FxJnfQgjMjZoEPMFmD2uo


That means for arbitrary inputs the code is deliberately equivalent across two paths (this is meant to distract you).

3) Decompilation: confusing on purpose

When we decompile, we see functions f0 … f16. A few key things stick out:

f0() is an anti-debug/anti-decompile check (looks for pycdc, decompyle3, uncompyle6, or a debugger via sys.gettrace()). If it trips, the program exits early with a decoy output.

f14(i): takes your input i and computes a fancy hash-mix → URL-safe Base64. (Explains the lines you saw.)

f12(i): hardcoded SHA-256 equality check. If your input matches a fixed digest, the program takes a secret path.

f13(k1, k2): the real payload; it decodes arrays of integers into a string using a small arithmetic/XOR transform, then permutes/joins the parts.

Some decompiled lines look impossible (e.g., x[k, i + len(k)]), which is just the decompiler getting confused by obfuscation. Disassembly shows the real operations are simple bit shifts and XORs.

4) What the decoy does — f14(i)

Disassembling shows f14(i) roughly does:

k = sha256(i)

s = blake2s(i, 32 bytes)

Mix them with a small bytewise tweak and return:

base64.urlsafe_b64encode(mix(k, s)).rstrip("=")


That’s why your runs with no/any input print harmless Base64. It’s a decoy.

Examples you saw:

Input "test_input" → -7-cWrPc3AqGqTGMiJb0r8FxJnfQgjMjZoEPMFmD2uo

Running the .pyc directly printed two different URL-safe lines as well.

5) The real gate — f12(i)

There’s a secret “password” path inside f15/f16:

f12(i) checks:

sha256(i) == "02ee5f37b7284fa385a3803975d3dbf18973c21e5bafd63f0ae1e21d16c29779"


If that exact input is provided, the program computes two small integers

k1 = int(i[:4])
k2 = int(i[4:6])


and then calls f13(k1, k2) to retrieve the final string (the flag).

Brute-forcing that SHA-256 preimage is not feasible. Instead, we read f13 and recover the flag directly.

6) The payload — f13(k1, k2)

The inner worker in f13 is a closure I’ll call fvdy. For each integer v in a table, it does:

ch = chr( ( ((v >> 1) - k2)  ^  (k1 & 0xff) )  & 0xff )


Then:

It decodes several arrays (8 chunks) with fvdy.

Reverses each chunk, applies a fixed permutation, then concatenates.

Result is the final string (flag).

If you scan small (k1, k2) pairs you quickly find a clean ASCII hit:

f13(81, 173)  →  "CTF{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}"


That exact string also appears for a few other equivalent pairs (because of & 0xff wraparounds), e.g. (209, 45).

7) Minimal reproducible extraction

If you want a tiny extractor that doesn’t run the program (so no anti-debug surprises), here’s a standalone script:

# extract_flag.py (Python 3.11+)
import marshal

PYC = "bytecode.pyc"  # path to the challenge file

with open(PYC, "rb") as f:
    data = f.read()

# .pyc header is 16 bytes on 3.7+; the code object follows
code = marshal.loads(data[16:])

ns = {}
exec(code, ns)  # load module objects without running __main__

flag = ns["f13"](81, 173)
print(flag)


Output:

CTF{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}


Use lowercase ctf{...} if the platform enforces that format:

ctf{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}

8) Why there were two lines on first run

When you ran the .pyc straight, it printed two URL-safe Base64 lines. That’s because the main coroutine tries two paths:

A straightforward f14(i) print (decoy).

A tiny in-memory bootstrap (marshal + exec) that builds a run(...) function and calls it on a “massaged” byte blob.
For random/empty input, this inner path degenerates to something equivalent to f14(i) (hence your harness showed verify ... True), but the values can differ because of the way the blob is sliced/mutated.

Both lines are not the flag — they’re just per-input hashy outputs.

9) Final answer

Flag: ctf{2944cec0c0f401a5fa538933a2f6210c279fbfc8548ca8ab912b493d03d2f5bf}
