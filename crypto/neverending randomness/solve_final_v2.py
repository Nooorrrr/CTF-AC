# solve_final_v2.py — robust final solver
# Works with ~200+ lines of your samples.txt

import sys, re, ast, binascii

N, M = 624, 397
MATRIX_A   = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF

K = 72          # 69 bytes (one 32-bit word each) + 3 leaked 32-bit words
FLAG_LEN = 69   # CTF{ + 64 hex + }

def untemper(y):
    y &= 0xFFFFFFFF
    # inverse temper
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    for _ in range(5): y ^= (y << 7) & 0x9D2C5680
    y ^= y >> 11
    y ^= y >> 22
    return y & 0xFFFFFFFF

class MT:
    def __init__(self):
        self.mt = [0]*N
        self.mti = N
    def seed_by_state(self, state_words, idx0):
        self.mt = state_words[:]
        self.mti = idx0 % N
    def extract_untempered(self):
        if self.mti >= N:
            for i in range(N):
                x = (self.mt[i] & UPPER_MASK) | (self.mt[(i+1)%N] & LOWER_MASK)
                xa = x >> 1
                if x & 1: xa ^= MATRIX_A
                self.mt[i] = (self.mt[(i+M)%N] ^ xa) & 0xFFFFFFFF
            self.mti = 0
        y = self.mt[self.mti]
        self.mti += 1
        return y

def load_samples(path):
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            m = re.search(r"(\{.*\})", ln)
            if not m: continue
            d = ast.literal_eval(m.group(1))
            samples.append(d)
    return samples

# GF(2) Gaussian elimination: rows are ints with ncols bits; solve A w = b
def gauss_gf2(A_rows, b_bits, ncols):
    rows = A_rows[:]
    b = b_bits[:]
    m = len(rows)
    row = 0
    pivots = []
    for col in range(ncols):
        mask = 1 << col
        piv = None
        for r in range(row, m):
            if rows[r] & mask:
                piv = r; break
        if piv is None:
            continue
        rows[row], rows[piv] = rows[piv], rows[row]
        b[row], b[piv] = b[piv], b[row]
        pivots.append(col)
        for r in range(m):
            if r!=row and (rows[r] & mask):
                rows[r] ^= rows[row]
                b[r]    ^= b[row]
        row += 1
        if row==m: break
    # back-sub to one solution
    w = 0
    for i in reversed(range(row)):
        col = pivots[i]
        rem = rows[i] & ~(1<<col)
        # parity of dot(rem, w)
        x = rem
        s = 0
        while x:
            c = (x & -x).bit_length()-1
            s ^= (w >> c) & 1
            x &= x-1
        val = b[i] ^ s
        if val: w |= (1<<col)
    return w

def poppar64(v):
    # parity of 64-bit chunk
    v ^= v >> 32
    v ^= v >> 16
    v ^= v >> 8
    v ^= v >> 4
    return (0x6996 >> (v & 0xF)) & 1

def parity_big(v):
    # parity of arbitrary-size int via 64-bit chunks
    p = 0
    mask = (1<<64)-1
    while v:
        p ^= poppar64(v & mask)
        v >>= 64
    return p

def train_byte_predictors(kstride=K, W=256, S=9000, ref_len=1000000):
    """
    Learn linear predictors mapping the last W decimated words (32*W bits)
    to the low-8 of target words at offsets 0..68.
    Large W and S -> accurate predictors.
    """
    # reference MT run
    ref = MT()
    st = [(0x6a09e667 ^ i*0x9e3779b1) & 0xFFFFFFFF for i in range(N)]
    ref.seed_by_state(st, 0)

    # generate enough untempered words
    untemp = [ref.extract_untempered() for _ in range(ref_len)]
    decim  = [untemp[i] for i in range(0, ref_len, kstride)]
    D = len(decim)
    if D <= W + S + 100:
        need = (W + S + 200) * kstride
        extra = need - ref_len
        for _ in range(extra):
            untemp.append(ref.extract_untempered())
        decim = [untemp[i] for i in range(0, len(untemp), kstride)]
        D = len(decim)

    nfeat = 32*W
    # Precompute feature rows for blocks b in [W .. W+S-1]
    feat_rows = []
    for b in range(W, W+S):
        # pack 32*W features into a single big int
        mask = 0
        bitpos = 0
        for j in range(b-W, b):
            w = decim[j]
            # append bits 0..31 (LSB-first)
            mask |= (w & 0xFFFFFFFF) << bitpos
            bitpos += 32
        feat_rows.append(mask)

    predictors = []
    for off in range(FLAG_LEN):
        # labels for S samples
        labels = [[] for _ in range(8)]
        for si,b in enumerate(range(W, W+S)):
            idx = b*kstride + off
            byte = untemp[idx] & 0xFF
            for bit in range(8):
                labels[bit].append((byte>>bit)&1)
        # solve 8 GF(2) systems
        weights = []
        for bit in range(8):
            w = gauss_gf2(feat_rows, labels[bit], nfeat)
            weights.append(w)
        predictors.append(weights)
    return predictors, W

def apply_predictor(weights, W, decim_window_words):
    # decim_window_words: list of W ints, oldest..latest
    # pack features into big int (LSB-first per word, words oldest..latest)
    mask = 0
    bitpos = 0
    for w in decim_window_words:
        mask |= (w & 0xFFFFFFFF) << bitpos
        bitpos += 32
    byte = 0
    for bit in range(8):
        if parity_big(weights[bit] & mask):
            byte |= (1<<bit)
    return byte

def main():
    if len(sys.argv) != 2:
        print("Usage: python solve_final_v2.py samples.txt")
        sys.exit(1)
    samples = load_samples(sys.argv[1])
    if not samples:
        print("No samples parsed.")
        sys.exit(1)

    # Build decimated untempered leak stream (concat all triples in order)
    leaks = []
    cts = []
    for s in samples:
        a,b,c = s["leak32"]
        leaks.extend([untemper(a), untemper(b), untemper(c)])
        cts.append(bytes.fromhex(s["ciphertext_hex"]))

    D = len(leaks)  # 3 per sample
    print(f"[*] Training predictors with W=256, S=9000 … (one-time)")
    predictors, W = train_byte_predictors(W=256, S=9000, ref_len=1000000)

    # choose a block index with enough history: need 3*j >= W  → j >= ceil(W/3)
    j = max((W + 2)//3, 90)   # with 200 samples, this is fine
    if 3*j > D:
        j = D//3 - 1
        if j < (W + 2)//3:
            raise RuntimeError("Not enough samples; collect ~250+ lines total.")
    window = leaks[3*j - W : 3*j]

    # Predict the 69 keystream bytes for block j, then decrypt
    ks = bytearray(apply_predictor(predictors[off], W, window) for off in range(FLAG_LEN))
    pt = bytes(a ^ b for a,b in zip(cts[j], ks))

    try:
        s = pt.decode()
    except:
        s = None
    print("[*] Decrypted block index:", j)
    print("[*] Plaintext:", s if s else pt)
    if s and s.startswith("CTF{") and s.endswith("}"):
        print("[*] FLAG:", s)
    else:
        # try neighboring block if needed
        for delta in (-1, +1, +2, -2):
            jj = j + delta
            if jj < (W+2)//3 or 3*jj > D: continue
            window2 = leaks[3*jj - W : 3*jj]
            ks2 = bytearray(apply_predictor(predictors[off], W, window2) for off in range(FLAG_LEN))
            pt2 = bytes(a ^ b for a,b in zip(cts[jj], ks2))
            try:
                s2 = pt2.decode()
            except:
                s2 = None
            if s2 and s2.startswith("CTF{") and s2.endswith("}"):
                print("[*] Decrypted neighbor block:", jj)
                print("[*] FLAG:", s2)
                return
        print("[!] Didn’t decode cleanly — grab ~50–100 more samples and rerun (accuracy grows with data).")

if __name__ == "__main__":
    main()
