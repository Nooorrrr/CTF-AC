# solve_xor_flag.py
# Récupère la clef (flag) d'un XOR à clé répétée, sachant que:
# - key_len = 69
# - key[0:4] = "CTF{", key[68] = "}"
# - key[4:68] sont des hex [0-9a-f]
# - Le plaintext est essentiellement ASCII lisible.

from pathlib import Path

CIPH_PATH = "out.bin"
KEY_LEN = 69

def is_printable_byte(b: int) -> bool:
    # ASCII imprimable + tab/CR/LF
    return (32 <= b <= 126) or b in (9, 10, 13)

def recover_key(cipher: bytes) -> bytes:
    key = [None] * KEY_LEN
    # Contraintes connues
    known = {0: ord('C'), 1: ord('T'), 2: ord('F'), 3: ord('{'), 68: ord('}')}
    for i, v in known.items():
        key[i] = v

    # Indices par position modulo KEY_LEN
    buckets = {r: [] for r in range(KEY_LEN)}
    for i, c in enumerate(cipher):
        buckets[i % KEY_LEN].append(c)

    # Alphabet restreint pour l'intérieur de CTF{...}
    hexset = b"0123456789abcdef"

    for r in range(KEY_LEN):
        if key[r] is not None:
            continue
        best_char, best_score = None, -1.0
        for ch in hexset:
            # Score = nombre d'octets déchiffrés imprimables (+ léger bonus espaces/lettres)
            plain_bytes = [c ^ ch for c in buckets[r]]
            score = sum(1 for pb in plain_bytes if is_printable_byte(pb))
            spaces = sum(1 for pb in plain_bytes if pb == 32)
            letters = sum(1 for pb in plain_bytes if (65 <= pb <= 90 or 97 <= pb <= 122))
            metric = score + spaces * 0.1 + letters * 0.01
            if metric > best_score:
                best_score, best_char = metric, ch
        key[r] = best_char

    return bytes(key)

def decrypt(cipher: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes([b ^ key[i % kl] for i, b in enumerate(cipher)])

def main():
    cipher = Path(CIPH_PATH).read_bytes()
    key = recover_key(cipher)
    print("Recovered FLAG/key:\n", key.decode("ascii"), "\n")

    # (Optionnel) écrire le plaintext pour vérifier
    try:
        pt = decrypt(cipher, key)
        Path("recovered_plaintext.txt").write_bytes(pt)
        print("Plaintext écrit dans recovered_plaintext.txt")
    except Exception as e:
        print("Déchiffrement/écriture du plaintext optionnel a échoué:", e)

if __name__ == "__main__":
    main()
