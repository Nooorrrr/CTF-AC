# Crypto CTF — _mistake_

> “We all make mistakes. It’s important to learn from them.”

This challenge hides a message inside **LWE** (_Learning With Errors_) samples—but with a design flaw that lets us recover the plaintext **without knowing the secret**. 👀

---

## 🧩 Challenge Files

You’re given a JSON file `mistake.txt` containing:

- a matrix \(A\) of size \(m \times n\),
- a vector \(b\) of size \(m\),
- metadata `meta` including \(q = 3329\), \(n = 128\), \(m = 808\), \(L = 552\), etc.

The hint “mistakes / learn from them” points straight at **LWE** (we “learn” from “errors”).

---

## 🔬 Quick Observations

1. **Tiny coefficients in \(A\)**  
   Entries of \(A\) lie in \(\{0,1,\dots,5,3324,\dots,3328\}\), i.e., in the range \([-5,5]\) when reduced mod \(q=3329\) (since \(3324 \equiv -5 \pmod{3329}\), etc.).  
   That’s unusually **small** for a robust inner product.

2. **Two clear levels in \(b\)**  
   Each \(b_i\) sits noticeably close to either \(0\) or \(q/4 \approx 832.25\); we do **not** see values clustering near \(q/2\) or \(3q/4\).  
   This strongly suggests a **binary** message \(m_i \in \{0,1\}\) encoded by adding \(q/4\) when the bit is 1.

3. **Noise window is tiny**  
   The term \(\langle a_i, s\rangle + e_i\) stays within a very small window (tens at most), which is **far** smaller than the half-gap \((q/4)/2 \approx 416\).  
   Consequence: we can **classify each \(b_i\)** as “close to 0” (bit 0) or “close to \(q/4\)” (bit 1) **without the secret**.  
   That’s the _mistake_ we exploit.

---

## 🧠 (Very) Brief LWE Reminder

Each line follows, modulo \(q\):

\[
b_i \equiv \langle a_i, s \rangle + e_i + m_i \cdot \frac{q}{4}.
\]

With small noise \(e_i\), the \(q/4\) offset for bit 1 should remain much larger than the uncertainty from \(\langle a_i,s\rangle + e_i\).  
Here, the “LWE part” is **so small** that we can ignore \(A\) and \(s\), and read bits directly from \(b\).

---

## 🛠️ Attack Plan

1. **Parse** the JSON to get \(b\) and \(q=3329\).
2. For each \(b_i\), compare the **cyclic distance** to \(0\) and to \(q/4\).
   - nearer to \(0\) ⇒ \(m_i = 0\)
   - nearer to \(q/4\) ⇒ \(m_i = 1\)  
     (Remember: values near \(q\) may actually be “near 0” modulo \(q\).)
3. **Take the first \(L = 552\) bits** (from metadata `L`).
4. **Pack bits into bytes** using **little-endian per byte** (first bit read = LSB).
5. **Decode as UTF-8** → you get the message/flag.

---

## 📦 Reproducible Solver

Save this as `solve.py` next to `mistake.txt`:

```python
import json

with open("mistake.txt", "r", encoding="utf-8") as f:
    data = json.load(f)

b = data["b"]
q = data["meta"]["q"]   # 3329
L = data["meta"]["L"]   # 552
step = q / 4.0          # 832.25

def bit_from_b(bi):
    """Return 0 or 1 depending on whether bi is closer (mod q) to 0 or q/4."""
    # cyclic distance to 0
    d0 = min(abs(bi - 0), q - abs(bi - 0))
    # cyclic distance to q/4
    d1 = min(abs(bi - step), q - abs(bi - step))
    return 0 if d0 <= d1 else 1

bits = [bit_from_b(int(x)) for x in b][:L]

# pack bits little-endian per byte (first bit read -> LSB)
out = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(bits):
            byte |= (bits[i + j] << j)
    out.append(byte)

print(out.decode("utf-8"))
```
