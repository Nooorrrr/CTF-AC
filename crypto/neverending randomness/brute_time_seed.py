# brute_time_seed.py
import time, binascii, random, argparse

def try_search(ciphertext_hex, leak32, pid, window_before, window_after, ts_center=None):
    ct = binascii.unhexlify(ciphertext_hex)
    flag_len = len(ct)
    if ts_center is None:
        ts_center = int(time.time())
    found = []
    for ts in range(ts_center - window_before, ts_center + window_after + 1):
        seed = ts ^ pid
        rng = random.Random(seed)
        ks = bytearray()
        while len(ks) < flag_len:
            ks.extend(rng.getrandbits(8).to_bytes(1, "big"))
        plain = bytes(a ^ b for a, b in zip(ct, ks[:flag_len]))
        if plain.startswith(b"CTF{") and plain.endswith(b"}"):
            inner = plain[4:-1]
            if len(inner) == 64 and all(chr(c).lower() in "0123456789abcdef" for c in inner):
                # verify leak32
                got = [rng.getrandbits(32) for _ in range(3)]
                if got == leak32:
                    return (ts, seed, plain.decode(), True)
                else:
                    # still return candidate if format matches (leak mismatch maybe due to bit-buffering)
                    return (ts, seed, plain.decode(), False)
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ct", required=True)   # ciphertext_hex
    parser.add_argument("--leak", required=True) # comma separated 3 ints
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--center", type=int, default=None)
    parser.add_argument("--before", type=int, default=3600) # seconds
    parser.add_argument("--after", type=int, default=0)
    args = parser.parse_args()

    leak32 = [int(x) for x in args.leak.split(",")]
    res = try_search(args.ct, leak32, args.pid, args.before, args.after, args.center)
    if res:
        ts, seed, flag, leak_ok = res
        print("FOUND:", flag)
        print("timestamp:", ts, "seed:", seed, "leak_confirmed:", leak_ok)
    else:
        print("No candidate in window.")
