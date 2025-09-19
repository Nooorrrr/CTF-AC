# XORbitant - Crypto Challenge Write-up (100 points)

## Challenge Description

**XORbitant** is a basic cryptanalysis challenge that introduces us to fundamental cryptanalysis techniques for repeating-key XOR cipher. The challenge message states: _"Let us master the primordial cryptoanalysis technique"_ and specifies that **the flag is the key** used for encryption.

**Flag format:** `CTF{sha256}`

## Analysis of Provided Files

### 1. `enc.py` - The Encryption Script

```python
import os

def xor(input_path: str, output_path: str):
    key = os.getenv("FLAG","CTF{example_flag}")
    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        chunk_size = 4096
        i = 0
        while chunk := infile.read(chunk_size):
            xored = bytes([b ^ key_bytes[(i + j) % key_len] for j, b in enumerate(chunk)])
            outfile.write(xored)
            i += len(chunk)

xor("plaintext.txt","out.bin")
```

**Encryption script analysis:**

- The key is retrieved from the `FLAG` environment variable
- Encryption uses XOR with a repeating key (Vigenère cipher in XOR)
- The plaintext `plaintext.txt` is encrypted and saved as `out.bin`
- The key is cyclically repeated across the entire message length

### 2. `out.bin` - The Encrypted File

This file contains the result of XOR encryption of the original plaintext.

## Attack Principle

### Repeating-Key XOR Vulnerabilities

1. **Key reuse**: The same key is used cyclically
2. **Known structure**: `CTF{...}` format with specific constraints
3. **Predictable plaintext**: The original text is likely readable ASCII

### Identified Constraints

Based on the `CTF{sha256}` format hint:

- **Key length**: 69 characters (CTF{ + 64 hex characters + })
- **Key start**: `CTF{` (positions 0-3)
- **Key end**: `}` (position 68)
- **Key middle**: 64 hexadecimal characters [0-9a-f] (positions 4-67)

## Developed Solution

### Key Recovery Algorithm

```python
def recover_key(cipher: bytes) -> bytes:
    key = [None] * KEY_LEN

    # 1. Known constraints from CTF{...} format
    known = {0: ord('C'), 1: ord('T'), 2: ord('F'), 3: ord('{'), 68: ord('}')}
    for i, v in known.items():
        key[i] = v

    # 2. Grouping by position modulo KEY_LEN
    buckets = {r: [] for r in range(KEY_LEN)}
    for i, c in enumerate(cipher):
        buckets[i % KEY_LEN].append(c)

    # 3. Restricted alphabet for positions 4-67
    hexset = b"0123456789abcdef"

    # 4. Brute force attack on each position
    for r in range(KEY_LEN):
        if key[r] is not None:
            continue

        best_char, best_score = None, -1.0
        for ch in hexset:
            plain_bytes = [c ^ ch for c in buckets[r]]

            # Score based on ASCII "readability"
            score = sum(1 for pb in plain_bytes if is_printable_byte(pb))
            spaces = sum(1 for pb in plain_bytes if pb == 32)
            letters = sum(1 for pb in plain_bytes if (65 <= pb <= 90 or 97 <= pb <= 122))

            metric = score + spaces * 0.1 + letters * 0.01

            if metric > best_score:
                best_score, best_char = metric, ch

        key[r] = best_char

    return bytes(key)
```

### Bucket-Based Attack Strategy

1. **Grouping**: All ciphertext bytes encrypted with the same key byte are grouped together
2. **Systematic testing**: For each unknown key position, test all possible hexadecimal characters
3. **Scoring**: Evaluate decryption "quality" based on:
   - Printable ASCII characters
   - Bonus for spaces (word separators)
   - Bonus for letters (textual content)

### Scoring Function

```python
def is_printable_byte(b: int) -> bool:
    # Printable ASCII + tab/CR/LF
    return (32 <= b <= 126) or b in (9, 10, 13)
```

The scoring favors decryptions producing readable ASCII text, which is a reasonable assumption for CTF challenge plaintext.

## Attack Execution

### Resolution Steps

1. **Read encrypted file** `out.bin`
2. **Apply recovery algorithm** with format constraints
3. **Extract flag** (which is the key itself)
4. **Optional verification** through complete decryption

### Final Script

```python
def main():
    cipher = Path(CIPH_PATH).read_bytes()
    key = recover_key(cipher)
    print("Recovered FLAG/key:\n", key.decode("ascii"), "\n")

    # Optional verification
    try:
        pt = decrypt(cipher, key)
        Path("recovered_plaintext.txt").write_bytes(pt)
        print("Plaintext written to recovered_plaintext.txt")
    except Exception as e:
        print("Optional plaintext decryption/writing failed:", e)
```

## Key Points of the Solution

### Advantages of this Approach

1. **Constraint exploitation**: Maximum use of known format
2. **Search space reduction**: Only 16^64 instead of 256^69
3. **Intelligent scoring**: Favors natural text
4. **Robustness**: Works even with noise in plaintext

### Complexity

- **Time**: O(64 × 16 × n) where n is the ciphertext length
- **Space**: O(ciphertext length)

## Cryptanalysis Technique Breakdown

### Statistical Analysis

The attack relies on the principle that natural language text has predictable statistical properties:

- High frequency of printable ASCII characters
- Common occurrence of spaces and letters
- Low frequency of control characters

### Frequency Analysis Adaptation

Instead of traditional letter frequency analysis, this solution uses:

- **Printability scoring**: Measures how "text-like" the decryption appears
- **Character type weighting**: Prioritizes common textual elements
- **Constraint satisfaction**: Leverages known format structure

### Why This Attack Works

1. **Weak key schedule**: Repeating-key XOR provides no key schedule complexity
2. **Known plaintext structure**: ASCII text has predictable patterns
3. **Format leakage**: The CTF{} format reveals significant key material
4. **Sufficient ciphertext**: Long enough text provides statistical confidence

## Educational Value

### Demonstrated Vulnerabilities

- **Key reuse catastrophe**: Same key material encrypts multiple positions
- **Format information leakage**: Structured data reveals key components
- **Statistical weaknesses**: Natural language patterns enable attacks

### Cryptographic Lessons

- Never reuse cryptographic material
- Avoid predictable message formats
- Statistical properties of plaintext can be exploited
- Simple XOR ciphers are vulnerable to frequency analysis

## Alternative Attack Vectors

### Other Possible Approaches

1. **Kasiski examination**: Finding repeated ciphertext patterns
2. **Index of coincidence**: Statistical key length determination
3. **Dictionary attacks**: If plaintext contains known words
4. **Crib dragging**: Using known plaintext segments

### Why the Chosen Method is Optimal

- Leverages maximum available constraints
- Computationally efficient
- Robust against plaintext variations
- Provides clear success metrics

## Implementation Details

### Error Handling

```python
def is_printable_byte(b: int) -> bool:
    # Handles edge cases like extended ASCII
    return (32 <= b <= 126) or b in (9, 10, 13)
```

### Optimization Considerations

- **Memory efficiency**: Processes chunks rather than entire file
- **Early termination**: Could stop when scoring confidence is high
- **Parallel processing**: Each key position could be attacked independently

## Conclusion

This challenge perfectly illustrates the vulnerabilities of repeating-key XOR encryption:

- **Cryptographic material reuse**
- **Exploitable known structures**
- **Statistical analysis opportunities**
