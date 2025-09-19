# Crypto CTF Challenge: "mistake" - Write-up

## 📋 Challenge Overview

**Challenge Name:** mistake  
**Category:** Cryptography  
**Server:** `nc ctf.ac.upt.ro 9541`  
**Description:** "We all make mistakes. It's important to learn from them."

This challenge involves a cryptographic scheme based on **Learning With Errors (LWE)** that contains a critical design flaw, allowing us to recover the hidden message without knowing the secret key.

---

## 📁 Getting Challenge Files

To obtain the challenge data, connect to the server:

```bash
nc ctf.ac.upt.ro 9541 > mistake.txt
```

This will download a JSON file containing:

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
- `s` is the secret vector (unknown)
- `e_i` is a small error term
- `m_i` is the message bit (0 or 1)
- The term `q/4` is added when the message bit is 1

### Key Observations After Data Examination

1. **Unusually Small Coefficients in Matrix A**

   - Matrix entries are constrained to `{0,1,2,3,4,5,3324,3325,3326,3327,3328}`
   - When reduced modulo q=3329, these represent the range `[-5, 5]`
   - This is extremely small for a secure LWE implementation

2. **Binary Clustering Pattern in Vector b**

   - Values in `b` cluster around two distinct levels:
     - Near `0` (representing message bit 0)
     - Near `q/4 ≈ 832.25` (representing message bit 1)
   - Clear separation between the two clusters
   - No values appear near `q/2` or `3q/4`

3. **Minimal Noise Impact**
   - The combined effect of `⟨a_i, s⟩ + e_i` is very small
   - Much smaller than the separation distance `q/4`
   - This allows direct bit classification without knowing the secret!

---

## 🎯 The Critical Vulnerability

The "mistake" in this LWE implementation is a **parameter selection flaw**:

- **Insufficient masking**: The noise and secret contribution is so small compared to the message encoding offset (`q/4`) that we can directly classify each `b_i` value
- **Direct bit recovery**: We can determine each message bit by simply checking whether `b_i` is closer to 0 or `q/4`
- **Bypassed security**: This completely circumvents the hardness of the LWE problem

### Mathematical Insight

For secure LWE, the term `⟨a_i, s⟩ + e_i` should be large enough to mask the message encoding. Here:

- `⟨a_i, s⟩` is bounded by `|s| * 5` (very small)
- `e_i` is also small
- Combined effect << `q/4` = 832.25

This creates **trivial distinguishability** between message bits.

---

## 🔧 Solution Strategy

### Step-by-Step Approach

1. **Data Extraction**

   - Parse the JSON structure from `mistake.txt`
   - Extract vector `b` and metadata parameters

2. **Bit Classification Algorithm**

   - For each `b_i`, calculate cyclic distances to 0 and `q/4`
   - Choose the nearest target as the decoded bit
   - Handle modular arithmetic wraparound correctly

3. **Message Reconstruction**

   - Extract the first `L = 552` bits from the classification
   - Pack bits into bytes using little-endian bit ordering
   - Decode the resulting bytes as UTF-8 text

4. **Flag Extraction**
   - The decoded text should contain the CTF flag

---

## 💻 Complete Solution Implementation

```python
import json

def solve_lwe_mistake():
    """
    Complete solver for the LWE mistake challenge.
    Exploits the small noise to recover the hidden message.
    """
    print("[*] Loading challenge data from mistake.txt...")

    try:
        with open("mistake.txt", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[!] Error: mistake.txt not found!")
        print("[!] Run: nc ctf.ac.upt.ro 9541 > mistake.txt")
        return None
    except json.JSONDecodeError:
        print("[!] Error: Invalid JSON format in mistake.txt")
        return None

    # Extract parameters
    b = data["b"]
    q = data["meta"]["q"]   # Should be 3329
    L = data["meta"]["L"]   # Should be 552 bits
    step = q / 4.0          # ~832.25

    print(f"[*] Parameters: q={q}, L={L}, samples={len(b)}")
    print(f"[*] Target values: 0 and {step:.2f}")

    def cyclic_distance(x, target, modulus):
        """Calculate minimum cyclic distance between x and target mod modulus."""
        diff = abs(x - target)
        return min(diff, modulus - diff)

    def classify_bit(bi):
        """
        Classify a b_i value as 0 or 1 based on proximity to 0 or q/4.
        Returns 0 if closer to 0, 1 if closer to q/4.
        """
        dist_to_zero = cyclic_distance(bi, 0, q)
        dist_to_quarter = cyclic_distance(bi, step, q)

        return 0 if dist_to_zero <= dist_to_quarter else 1

    print("[*] Classifying bits...")

    # Extract message bits
    message_bits = []
    bit_counts = {0: 0, 1: 0}

    for i in range(min(L, len(b))):
        bit = classify_bit(int(b[i]))
        message_bits.append(bit)
        bit_counts[bit] += 1

    print(f"[*] Bit distribution: 0s={bit_counts[0]}, 1s={bit_counts[1]}")

    # Pack bits into bytes (little-endian per byte)
    print("[*] Packing bits into bytes...")
    message_bytes = bytearray()

    for i in range(0, len(message_bits), 8):
        byte_value = 0
        for j in range(8):
            if i + j < len(message_bits):
                # Little-endian: first bit becomes LSB
                byte_value |= (message_bits[i + j] << j)
        message_bytes.append(byte_value)

    # Decode as UTF-8
    try:
        decoded_message = message_bytes.decode("utf-8")
        print(f"[*] Successfully decoded {len(decoded_message)} characters")
        return decoded_message
    except UnicodeDecodeError as e:
        print(f"[!] UTF-8 decode error: {e}")
        # Try to find valid UTF-8 portion
        for i in range(len(message_bytes) - 1, 0, -1):
            try:
                partial = message_bytes[:i].decode("utf-8")
                print(f"[*] Partial decode successful ({i} bytes)")
                return partial
            except UnicodeDecodeError:
                continue
        return None

def main():
    """Main execution function."""
    print("=" * 60)
    print("    LWE 'mistake' Challenge Solver")
    print("=" * 60)

    result = solve_lwe_mistake()

    if result:
        print("\n" + "=" * 60)
        print("RECOVERED MESSAGE:")
        print("=" * 60)
        print(result)
        print("=" * 60)

        # Look for flag pattern
        if "ctf{" in result.lower():
            print("\n[+] FLAG FOUND!")
        else:
            print("\n[*] Check the message above for the flag")
    else:
        print("\n[!] Failed to recover the message")

if __name__ == "__main__":
    main()
```

---

## 🏃 Step-by-Step Execution

### 1. Obtain Challenge Data

```bash
# Download the challenge file
nc ctf.ac.upt.ro 9541 > mistake.txt

# Verify the file was created
ls -la mistake.txt
```

### 2. Run the Solver

```bash
# Save the solver as solve.py
python3 solve.py
```

---
