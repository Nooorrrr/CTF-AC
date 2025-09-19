# Hidden in the Cartridge - Write-up

**Challenge:** Hidden in the Cartridge  
**Points:** 100  
**Category:** Reverse Engineering / Forensics  
**Author:** AAntioch

## Description

During a test session on the Retro-Arcade emulator, I found a corrupted copy of the classic Space Invaders. The game won't start, but the memory logs remain in the ROM file. Rumor has it that the developers used to leave hidden messages in the test cartridges. Can you help me fix this copy?

## Files Provided

- `space_invaders.nes` - A corrupted NES ROM file
- `READ_ME_FIRST.md` - A decoy file containing only a rickroll link

## Initial Analysis

### File Inspection

First, let's examine what we have:

```bash
file space_invaders.nes
hexdump -C space_invaders.nes | head -20
```

The file appears to be a NES ROM file, but there's something suspicious about it.

### NES ROM Format Analysis

A proper NES ROM file starts with a 16-byte iNES header:

- Bytes 0-3: `4E 45 53 1A` ("NES\x1A")
- Byte 4: Number of PRG-ROM banks (16 KiB units)
- Byte 5: Number of CHR-ROM banks (8 KiB units)
- Remaining bytes: Various flags and settings

When examining our file:

```bash
hexdump -C space_invaders.nes | head -1
```

We can see the header starts correctly with `4E 45 53 1A`, but the PRG and CHR ROM bank counts are **both 0**. This explains why the game won't start - an emulator sees this as "no ROM data available" and refuses to load it.

Even if we were to fix the header, the binary data doesn't contain valid NES executable code. The interrupt vectors (NMI/RESET/IRQ) at the end of PRG-ROM don't point to valid addresses in the expected range ($8000-$FFFF).

**Conclusion:** This isn't actually a corrupted game - it's a deliberately crafted container hiding something else.

## Finding the Hidden Data

### String Analysis

Let's search for ASCII strings in the file:

```bash
strings space_invaders.nes
```

Near the end of the file, we find interesting entries that look like memory logs:

```
[1987-06-15 10:32:22] INFO   - Emulator paused?
[1987-06-15 10:32:25] INFO   - Emulator shutdown complete??
```

But more importantly, we discover several blocks of data in an unusual format:

```
63$$$74$$$66$$$7b$$$39$$$66$$$31$$$62$$$34$$$33$$$...
```

### Pattern Recognition

These blocks contain:

- Hexadecimal pairs (2 characters each)
- Separated by `$$$` delimiters
- Multiple such blocks throughout the file

Let's convert the first few hex pairs to ASCII:

- `63` = 'c'
- `74` = 't'
- `66` = 'f'
- `7b` = '{'

This looks like the beginning of a CTF flag!

## Solution

### Automated Extraction

We can use a regular expression to find all blocks matching this pattern and decode them:

```python
import re

# Read the binary file
with open("space_invaders.nes", "rb") as f:
    data = f.read()

# Find all hex blocks separated by $$$
pattern = rb'([0-9a-fA-F]{2}(?:\$\$\$[0-9a-fA-F]{2}){3,})'
chunks = re.findall(pattern, data)

# Decode each chunk and concatenate
flag = ''
for chunk in chunks:
    hex_values = chunk.split(b'$$$')
    decoded = ''.join(chr(int(hex_val, 16)) for hex_val in hex_values)
    flag += decoded

print(flag)
```

### Alternative One-liner

```bash
python3 -c "
import re
b = open('space_invaders.nes','rb').read()
chunks = re.findall(rb'([0-9a-fA-F]{2}(?:\$\$\$[0-9a-fA-F]{2}){3,})', b)
flag = ''.join(''.join(chr(int(x,16)) for x in c.split(b'\$\$\$')) for c in chunks)
print(flag)
"
```

## Flag

```
ctf{9f1b438164dbc8a6249ba5c66fc0d6195b5388beed890680bf616021f2582248}
```
