import json

# 1) Charger le fichier
with open("mistake.txt", "r", encoding="utf-8") as f:
    data = json.load(f)

A = data["A"]          # non utilisé pour le décodage à cause de la faiblesse du jeu
b = data["b"]
q = data["meta"]["q"]  # 3329
L = data["meta"]["L"]  # 552
step = q / 4.0         # 832.25

def bit_from_b(bi):
    """Retourne 0 ou 1 selon que bi est plus proche de 0 ou de q/4, sur Z_q."""
    # distance cyclique à 0
    d0 = min(abs(bi - 0), q - abs(bi - 0))
    # distance cyclique à q/4
    d1 = min(abs(bi - step), q - abs(bi - step))
    return 0 if d0 <= d1 else 1

# 2) Estimer les bits (sur l'ensemble, puis tronquer à L bits utiles)
bits = [bit_from_b(int(x)) for x in b][:L]

# 3) Emballer en octets (little-endian par octet)
out = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(bits):
            byte |= (bits[i + j] << j)  # LSB en premier
    out.append(byte)

# 4) Afficher
print(out.decode("utf-8"))
