# solve_final.py (adaptive, runs on ~200 samples)
import sys, re, ast, binascii

N, M = 624, 397
MATRIX_A   = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
K = 72
FLAG_LEN = 69

def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7)  & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

def untemper(y):
    y &= 0xFFFFFFFF
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

# GF(2) Gaussian elimination. Rows are ints with ncols bits.
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
    # Back-sub
    w = 0
    for i in reversed(range(row)):
        col = pivots[i]
        rem = rows[i] & ~(1<<col)
        s = 0
        x = rem
        while x:
            c = (x & -x).bit_length()-1
            s ^= (w >> c) & 1
            x &= x-1
        val = b[i] ^ s
        if val: w |= (1<<col)
    return w

def train_byte_predictors(kstride=K, W=32, S=1300, ref_len=120000):
    """
    Learn linear predictors mapping the last W decimated words (32*W bits)
    to the low-8 of target words at offsets 0..68. Keeps systems overdetermined: S >= 32*W.
    """
    if S < 32*W:
        S = 32*W + 50
    # reference untempered stream
    ref = MT()
    st = [(0x6a09e667 ^ i*0x9e3779b1) & 0xFFFFFFFF for i in range(N)]
    ref.seed_by_state(st, 0)
    untemp = [ref.extract_untempered() for _ in range(ref_len)]
    decim  = [untemp[i] for i in range(0, ref_len, kstride)]
    D = len(decim)
    if D <= W + S + 5:
        # increase ref_len automatically
        need = (W + S + 10) * kstride
        extra = need - ref_len
        untemp.extend(ref.extract_untempered() for _ in range(extra))
        decim  = [untemp[i] for i in range(0, len(untemp), kstride)]
        D = len(decim)

    # Precompute feature rows for blocks b in [W .. W+S-1]
    nfeat = 32*W
    feat_rows = []
    for b in range(W, W+S):
        mask = 0
        bitpos = 0
        for j in range(b-W, b):
            w = decim[j]
            for i in range(32):
                if (w>>i) & 1:
                    mask |= (1<<bitpos)
                bitpos += 1
        feat_rows.append(mask)

    predictors = []
    for off in range(FLAG_LEN):
        # build labels for S samples
        labels = [[] for _ in range(8)]
        for si,b in enumerate(range(W, W+S)):
            idx = b*kstride + off
            byte = untemp[idx] & 0xFF
            for bit in range(8):
                labels[bit].append((byte>>bit)&1)
        weights = []
        for bit in range(8):
            w = gauss_gf2(feat_rows, labels[bit], nfeat)
            weights.append(w)
        predictors.append(weights)
    return predictors, W

def apply_predictor(weights, W, decim_window_words):
    mask = 0
    bitpos = 0
    for w in decim_window_words:
        for i in range(32):
            if (w>>i) & 1:
                mask |= (1<<bitpos)
            bitpos += 1
    byte = 0
    for bit in range(8):
        v = weights[bit] & mask
        # parity popcount
        v ^= v >> 32
        v ^= v >> 16
        v ^= v >> 8
        v ^= v >> 4
        v &= 0xF
        parity = (0x6996 >> v) & 1
        if parity:
            byte |= (1<<bit)
    return byte

def main():
    if len(sys.argv) != 2:
        print("Usage: python solve_final.py samples.txt")
        sys.exit(1)
    samples = load_samples(sys.argv[1])
    if not samples:
        print("No samples parsed.")
        sys.exit(1)

    # Build decimated untempered leak stream (concat all triples)
    leaks = []
    cts = []
    for s in samples:
        a,b,c = s["leak32"]
        leaks.extend([untemper(a), untemper(b), untemper(c)])
        cts.append(bytes.fromhex(s["ciphertext_hex"]))

    D = len(leaks)             # number of decimated words you have (3 per sample)
    # Train predictors with a small W that guarantees solvable systems
    print(f"[*] Training predictors with W=32, S=1300 on synthetic reference …")
    predictors, W = train_byte_predictors(W=32, S=1300, ref_len=120000)

    # Pick a block index j that has at least W decimated words of history.
    # Each block contributes 3 decimated words, so need 3*j >= W
    j = max((W + 2)//3, 20)
    if 3*j > D:
        # If you have very few samples, fall back to the last viable block.
        j = D//3 - 1
        if j < (W + 2)//3:
            raise RuntimeError("Not enough samples; collect ~50 more lines.")
    window = leaks[3*j - W : 3*j]  # last W decimated words before block j

    # Predict 69 keystream bytes for block j and decrypt
    ks = bytearray()
    for off in range(FLAG_LEN):
        ks.append(apply_predictor(predictors[off], W, window))
    pt = bytes([a ^ b for a,b in zip(cts[j], ks)])
    try:
        s = pt.decode()
    except:
        s = None
    print("[*] Decrypted block index:", j)
    print("[*] Plaintext:", pt if not s else s)
    if s and s.startswith("CTF{") and s.endswith("}"):
        print("[*] FLAG:", s)

if __name__ == "__main__":
    main()
