# Disco Dance - CTF Challenge Write-up

## Challenge Information

- **Name**: disco_dance
- **Points**: 218
- **Category**: Cryptography/Web
- **Flag Format**: `CTF{sha256}`

**Challenge Description:**

> I heard disco parties can be pretty random and chaotic. Let's see just how chaotic.

## Challenge Analysis

### Files Provided

1. **challenge.txt** - Challenge description
2. **route.ts** - Discord API proxy implementation
3. **server.py** - Main challenge server
4. **solve.py** - Solution script

### Understanding the Challenge

The challenge consists of a cryptographic service that:

1. **Uses Discord messages as randomness source** - Instead of proper randomness, it fetches the last 5 messages from a Discord channel
2. **Encrypts the flag** using AES-CBC with a key derived from these messages
3. **Returns the encrypted flag** in Base64 format

### Key Components Analysis

#### 1. Discord Proxy (`route.ts`)

```typescript
// Proxies requests to Discord API, swapping fake token for real token
const fake = process.env.FAKE_DISCORD_TOKEN;
const real = process.env.DISCORD_BOT_TOKEN;
```

The proxy allows the challenge server to access Discord API through a public endpoint.

#### 2. Server Logic (`server.py`)

```python
def get_random() -> bytes:
    # Fetches last 5 messages from Discord channel
    url = f"https://proxy-gamma-steel-32.vercel.app/api/proxy/channels/1416908413375479891/messages?limit=5"
    # ...
    concatenated = "".join(msg["content"] for msg in messages).encode("utf-8")
    return concatenated

def encrypt(data: bytes, key: bytes) -> str:
    # Derives AES key using SHA256 of the "random" data
    digest = SHA256.new()
    digest.update(key)
    aes_key = digest.digest()

    # Uses proper random IV (this part is secure)
    iv = get_random_bytes(16)

    # AES-CBC encryption with PKCS#7 padding
    padded_data = pad(data, AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)

    return base64.b64encode(iv + ciphertext).decode()
```

## Vulnerability

The critical vulnerability is in the **pseudorandom number generation**:

- Instead of using a cryptographically secure random number generator
- The server uses **publicly accessible Discord messages** as the "random" seed
- These messages can be fetched by anyone using the same proxy endpoint
- This makes the encryption key **predictable and recoverable**

## Solution Strategy

1. **Connect to the challenge server** to get the encrypted flag
2. **Fetch the same Discord messages** that were used to generate the key
3. **Recreate the encryption key** by concatenating and hashing the messages
4. **Decrypt the flag** using AES-CBC

## Implementation

### Solution Script (`solve.py`)

The solution implements both automatic and manual modes:

```python
def fetch_encrypted_from_remote(host: str, port: int) -> str:
    """Retrieve encrypted flag from challenge server"""
    with socket.create_connection((host, port), timeout=10) as s:
        s_file = s.makefile("rwb", buffering=0)
        line = s_file.readline().decode("utf-8", errors="replace").strip()

    # Parse the response to extract 'encrypted' field
    try:
        d = literal_eval(line)
        if isinstance(d, dict) and "encrypted" in d:
            return d["encrypted"]
    except Exception:
        m = re.search(r"'encrypted'\s*:\s*'([^']+)'", line)
        if m:
            return m.group(1)
    raise RuntimeError(f"Could not extract 'encrypted' from: {line}")

def fetch_last_5_messages(url: str) -> List[str]:
    """Fetch the last 5 messages from Discord channel via proxy"""
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()

    if not isinstance(data, list):
        raise RuntimeError("Unexpected proxy response (not a list).")

    msgs = [str(item.get("content", "")) for item in data]
    if len(msgs) < 5:
        raise RuntimeError(f"Less than 5 messages received: {len(msgs)}")

    return msgs[:5]

def derive_key_from_messages(messages: List[str]) -> bytes:
    """Derive AES key from concatenated message contents"""
    concatenated = "".join(messages).encode("utf-8")
    digest = SHA256.new(concatenated).digest()
    return digest

def decrypt_flag(encrypted_b64: str, key32: bytes) -> str:
    """Decrypt Base64(IV || CIPHERTEXT) using AES-CBC"""
    raw = base64.b64decode(encrypted_b64)
    if len(raw) < 16:
        raise ValueError("Encrypted blob too short (no IV).")

    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key32, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8", errors="strict")
```

## Execution

### Automatic Mode

```bash
python solve.py auto
```

### Manual Mode

```bash
python solve.py manual
```

## Solution Walkthrough

Based on the provided screenshot, here's what happens during execution:

1. **Server Connection**: Connect to `ctf.ac.upt.ro:9090`
2. **Get Encrypted Flag**: Receive Base64-encoded encrypted flag
3. **Fetch Messages**: Get the 5 Discord messages used as "randomness":
   ```
   [1] aaaaaaaa
   [2] aaaaaaaa
   [3] aaaaaaaa
   [4] aaaaaaaa
   [5] aaaaaaaa
   ```
4. **Key Derivation**: SHA256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
5. **Decryption**: Use derived key to decrypt the flag
6. **Result**: `CTF{55ba4939edd5611a7ab797529b51dae47989b3c5a99f2ffc82e4b2c74d03e56}`

## Flag

```
CTF{55ba4939edd5611a7ab797529b51dae47989b3c5a99f2ffc82e4b2c74d03e56}
```
