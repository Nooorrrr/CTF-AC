# Crypto CTF Challenge: "mistake" - Write-up

## 📋 Challenge Overview

**Challenge Name:** mistake  
**Category:** Cryptography  
**Description:** "We all make mistakes. It's important to learn from them."

This challenge involves a cryptographic scheme based on **Learning With Errors (LWE)** that contains a critical design flaw, allowing us to recover the hidden message without knowing the secret key.

---

## 📁 Challenge Files

The challenge provides a JSON file `mistake.txt` containing:

- Matrix **A** of dimensions `m × n`
- Vector **b** of size `m`
- Metadata including various parameters:
  - `q = 3329` (modulus)
  - `n = 128` (secret dimension)
  - `m = 808` (number of samples)
  - `L = 552` (message length in bits)

---

## 🔍 Initial Analysis

### Understanding LWE

Learning With Errors (LWE) is a cryptographic problem where each sample follows the equation:

```
b_i ≡ ⟨a_i, s⟩ + e_i + m_i · (q/4) (mod q)
```

Where:

- `a_i` is a row vector from matrix A
- `s` is the secret vector
- `e_i` is a small error term
- `m_i` is the message bit (0 or 1)
- The term `q/4` is added when the message bit is 1

### Key Observations

1. **Unusually Small Coefficients in A**

   - Matrix entries are constrained to `{0,1,2,3,4,5,3324,3325,3326,3327,3328}`
   - When reduced modulo q=3329, these represent the range `[-5, 5]`
   - This is extremely small for a secure LWE implementation

2. **Binary Clustering in Vector b**

   - Values in `b` cluster around two distinct levels:
     - Near `0` (representing message bit 0)
     - Near `q/4 ≈ 832.25` (representing message bit 1)
   - No values appear near `q/2` or `3q/4`

3. **Minimal Noise Window**
   - The combined effect of `⟨a_i, s⟩ + e_i` is very small
   - Much smaller than the separation `q/4`
   - This allows classification without knowing the secret!

---

## 🎯 The Vulnerability

The "mistake" in this implementation is that the noise and secret contribution is so small compared to the message encoding offset (`q/4`) that we can directly classify each `b_i` value as either:

- **Close to 0** → message bit = 0
- **Close to q/4** → message bit = 1

This completely bypasses the security of the LWE problem.

---

## 🔧 Solution Strategy

1. **Parse the Data Structure**

   - Extract vector `b` and parameters from JSON
   - Focus on `q`, `L` (message length)

2. **Implement Distance-Based Classification**

   - For each `b_i`, calculate cyclic distance to both 0 and `q/4`
   - Choose the closer target as the decoded bit

3. **Handle Modular Arithmetic**

   - Account for wraparound: values near `q` may actually be close to 0
   - Use minimum cyclic distance calculation

4. **Bit Extraction and Packing**
   - Extract first `L = 552` bits
   - Pack into bytes using little-endian bit order
   - Decode as UTF-8 text

---

## 💻 Implementation

```python
import json

def solve_lwe_mistake(filename):
    """
    Solve the LWE mistake challenge by exploiting the small noise.
    """
    # Load challenge data
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    b = data["b"]
    q = data["meta"]["q"]   # 3329
    L = data["meta"]["L"]   # 552 bits
    step = q / 4.0          # ~832.25

    def classify_bit(bi):
        """
        Classify a b_i value as 0 or 1 based on proximity to 0 or q/4.
        Uses cyclic distance to handle modular arithmetic correctly.
        """
        # Cyclic distance to 0
        dist_to_zero = min(abs(bi - 0), q - abs(bi - 0))

        # Cyclic distance to q/4
        dist_to_quarter = min(abs(bi - step), q - abs(bi - step))

        return 0 if dist_to_zero <= dist_to_quarter else 1

    # Extract message bits
    message_bits = []
    for i in range(L):
        bit = classify_bit(int(b[i]))
        message_bits.append(bit)

    # Pack bits into bytes (little-endian per byte)
    message_bytes = bytearray()
    for i in range(0, len(message_bits), 8):
        byte_value = 0
        for j in range(8):
            if i + j < len(message_bits):
                byte_value |= (message_bits[i + j] << j)
        message_bytes.append(byte_value)

    # Decode as UTF-8
    return message_bytes.decode("utf-8")

if __name__ == "__main__":
    result = solve_lwe_mistake("mistake.txt")
    print(f"Recovered message: {result}")
```

---

## 🏃 Execution Steps

1. Save the solver script as `solve.py`
2. Place `mistake.txt` in the same directory
3. Run: `python3 solve.py`
4. The script will output the recovered flag

---

## 🛡️ Security Analysis

### Why This Attack Works

- **Insufficient Noise**: The error terms are too small relative to the message encoding
- **Poor Parameter Selection**: Matrix coefficients bounded to `[-5,5]` provide minimal security
- **Clear Signal Separation**: The `q/4` offset creates easily distinguishable clusters

### Proper LWE Implementation Should Include

1. **Larger Error Distribution**: Noise should be significant compared to signal separation
2. **Wider Coefficient Range**: Matrix entries should span a larger portion of the modulus space
3. **Error Correction**: Implement coding schemes to handle larger noise without information leakage
4. **Parameter Validation**: Ensure security parameters meet established cryptographic standards

---

## 🎓 Learning Outcomes

This challenge demonstrates:

- The critical importance of proper parameter selection in lattice-based cryptography
- How implementation flaws can completely compromise theoretical security
- The relationship between noise, signal separation, and security in LWE-based schemes
- Practical cryptanalysis techniques for identifying and exploiting structural weaknesses

---

## 📚 References

- [Learning With Errors Problem](https://en.wikipedia.org/wiki/Learning_with_errors)
- [Lattice-based Cryptography](https://en.wikipedia.org/wiki/Lattice-based_cryptography)
- [Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

_This write-up is for educational purposes in cryptographic analysis and CTF problem solving._
