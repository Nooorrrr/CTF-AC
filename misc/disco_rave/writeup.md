# Disco Rave - CTF Challenge Writeup

## Challenge Information

- **Name**: disco_rave
- **Points**: 293
- **Category**: Cryptography/Web
- **Flag Format**: `CTF{sha256}`

## Challenge Description

> This is so infuriating! I know exactly what to do, but those damn trolls won't let me! This feels like that prisoner's dilemma I heard about. Automatic spam will be banned, manual spam is fine.

## Initial Analysis

The challenge provides several files:

- `challenge.txt` - Challenge description
- `route.ts` - Discord API proxy implementation
- `server.py` - Main server that encrypts the flag
- `solve.py` - Solution script

## Understanding the Challenge

### 1. Server Analysis (`server.py`)

The server does the following:

1. Fetches random data from two Discord channels via a proxy
2. Uses this data as a seed for AES encryption
3. Encrypts the flag using AES-CBC mode
4. Returns the encrypted flag to clients

Key function `get_random()`:

```python
def get_random() -> bytes:
    channels = [
        "1416908413375479891",
        "1417154025371209852",
    ]
    # Fetches last 10 messages from each channel
    # Concatenates content + timestamp for each message
    # Returns as bytes for encryption seed
```

### 2. Proxy Analysis (`route.ts`)

The proxy:

- Acts as a middleware between the client and Discord API
- Requires authentication with a fake token
- Replaces the fake token with a real Discord bot token
- Handles CORS headers for web requests

### 3. The Prisoner's Dilemma

The challenge hint mentions "prisoner's dilemma" and "automatic spam will be banned, manual spam is fine". This suggests:

- We need to interact with Discord channels manually
- Automated requests might be rate-limited or blocked
- The solution requires understanding Discord's message ordering and timestamps

## Solution Strategy

### Method 1: Automatic (via Proxy)

1. Connect to the challenge server to get encrypted flag
2. Use the proxy to fetch messages from Discord channels
3. Reconstruct the seed and decrypt the flag

### Method 2: Manual (Snowflake Method)

1. Get encrypted flag from server
2. Manually extract message IDs (snowflakes) from Discord
3. Convert snowflakes to timestamps
4. Reconstruct seed and decrypt flag

## Key Insights

### Discord Snowflakes

Discord message IDs are snowflakes that encode timestamp information:

```python
def snowflake_to_timestamp_iso(snowflake: int) -> str:
    ts_ms = (snowflake >> 22) + DISCORD_EPOCH_MS
    sec = ts_ms // 1000
    micros = (ts_ms % 1000) * 1000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=micros)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "+00:00")
```

### Seed Reconstruction

The seed is built by concatenating `content + timestamp` for each message:

```python
def build_seed_from_snowflakes() -> bytes:
    all_chunks: List[str] = []
    for cid in CHANNELS:
        pairs = ask_pairs_for_channel(cid)
        for content, mid in pairs:
            snow = int(mid)
            ts_iso = snowflake_to_timestamp_iso(snow)
            all_chunks.append(f"{content}{ts_iso}")
    return "".join(all_chunks).encode("utf-8")
```

## Solution Implementation

The complete solution script (`solve.py`) provides three modes:

### 1. Auto Mode

```bash
python solve.py auto
```

Fully automated using the proxy.

### 2. Manual Mode

```bash
python solve.py manual
```

Semi-automated - user provides encrypted flag, script fetches via proxy.

### 3. Snowflake Mode (Recommended)

```bash
python solve.py snowflake
```

Fully manual - user provides both encrypted flag and message data.

## Step-by-Step Solution

### 1. Get Encrypted Flag

Connect to `ctf.ac.upt.ro:9240` to receive the encrypted flag:

```
{'encrypted': 'nAeCxRIQVzpoZD/n2uUE/vdj49DXSoFR2aE9ijjz7XNVLoy39AK19kE8qY+q8mS8XMbe7GG+DqnciNNipkg7obin6p2G'}
```

### 2. Extract Message Data

For each channel, collect the last 10 messages in order (most recent → oldest):

**Channel 1416908413375479891:**

```
a|1417286290567744
a|1417286288318426
a|1417286286137364
a|1417286283448155
a|1417286276438950
a|1417286272963317
a|1417286271058968
a|1417286269075067
a|1417286267363659
```

**Channel 1417154025371209852:**

```
a|1417286251824025
a|1417286249504404
a|1417286244618214
a|1417286242852147
a|1417286240474107
a|1417286238074838
a|1417286235675689
a|1417286234195234
a|1417286232429432
```

### 3. Run Solution

```bash
python solve.py snowflake
```

Input the encrypted flag and message data when prompted.

## Final Result

```
✅ FLAG: CTF{a83a34f87919054eddbe03beefeddc1c7eeeeeeacf9d96af6d1e3c34494dfacc}
```
