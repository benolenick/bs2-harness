#!/usr/bin/env python3
"""Portable phpass (WordPress $P$) cracker — no GPU, multiprocess. Self-contained."""
import sys, hashlib, multiprocessing as mp, itertools, time

I64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _enc64(b):
    out = []; i = 0
    while i < len(b):
        v = b[i]; i += 1
        out.append(I64[v & 0x3f])
        if i < len(b): v |= b[i] << 8
        out.append(I64[(v >> 6) & 0x3f])
        if i >= len(b): break
        i += 1
        if i < len(b): v |= b[i] << 16
        out.append(I64[(v >> 12) & 0x3f])
        if i >= len(b): break
        i += 1
        out.append(I64[(v >> 18) & 0x3f])
    return "".join(out)

def phpass(pw, setting):
    # setting = $P$ + countchar + salt(8)
    count = 1 << I64.index(setting[3])
    salt = setting[4:12].encode()
    pw = pw.encode()
    h = hashlib.md5(salt + pw).digest()
    for _ in range(count):
        h = hashlib.md5(h + pw).digest()
    return setting[:12] + _enc64(h)[:22]

def worker(args):
    target, chunk = args
    setting = target[:12]
    for w in chunk:
        try:
            if phpass(w, setting) == target:
                return w
        except Exception:
            continue
    return None

def main():
    target = sys.argv[1]
    wl = sys.argv[2]
    maxw = int(sys.argv[3]) if len(sys.argv) > 3 else 300000
    t0 = time.time()
    with open(wl, encoding="latin-1") as f:
        words = [ln.rstrip("\n") for ln in itertools.islice(f, maxw)]
    ncpu = mp.cpu_count()
    csz = max(1, len(words) // (ncpu * 8))
    chunks = [(target, words[i:i+csz]) for i in range(0, len(words), csz)]
    with mp.Pool(ncpu) as pool:
        for res in pool.imap_unordered(worker, chunks):
            if res is not None:
                pool.terminate()
                print(f"CRACKED {target} : {res}   ({time.time()-t0:.1f}s, {ncpu} cores)")
                return
    print(f"NOTFOUND {target}  (tried {len(words)} words in {time.time()-t0:.1f}s)")

if __name__ == "__main__":
    main()
