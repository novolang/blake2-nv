# Writes ../generated_vectors_tests.nv: BLAKE2b and BLAKE2s digests over a fixed
# set of lengths with every combination of key, salt, personalisation and
# digest length, produced by hashlib (OpenSSL-independent: CPython's own
# BLAKE2 code); and the intermediate values hashlib does not expose (parameter
# block words, G, a round, the compression function) produced by the
# pure-Python reference in rfc_check.py, which asserts on import that it
# agrees with hashlib.  Run with `python3 -I generate.py` from this
# directory; the output is committed.
import hashlib, os, random, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rfc_check import B, S, SIGMA

rng = random.Random(7693)

def det(label, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(label.encode() + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:n]

def sgn(x, w):
    x &= (1 << w) - 1
    if w == 32:
        return x
    r = x - (1 << w) if x >= 1 << (w - 1) else x
    assert r != -(1 << 63)
    return r

def q(b): return '"' + b.hex() + '"'

LENS = [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 191, 192, 193, 255, 256, 257, 300, 1000]

def digest_rows(V, hf):
    mx = 64 if V is B else 32
    sw = 16 if V is B else 8
    rows = []
    for i, n in enumerate(LENS):
        msg = det(f"{V.name}m{n}", n)
        rows.append((msg, b"", b"", b"", mx, hf(msg, digest_size=mx).digest()))
    # digest lengths, unkeyed
    for ol in list(range(1, mx + 1)):
        msg = det(f"{V.name}o{ol}", ol * 3 % 97)
        rows.append((msg, b"", b"", b"", ol, hf(msg, digest_size=ol).digest()))
    # keys, every length
    for kl in range(1, mx + 1):
        key = det(f"{V.name}k{kl}", kl)
        for n in (0, 1, kl, V.block - 1, V.block, V.block + 1, 200):
            msg = det(f"{V.name}km{kl}-{n}", n)
            ol = mx if (kl + n) % 3 else 32 if V is B else 20
            rows.append((msg, key, b"", b"", ol, hf(msg, key=key, digest_size=ol).digest()))
    # salt and personalisation
    for i in range(12):
        n = LENS[(i * 5) % len(LENS)]
        msg = det(f"{V.name}sm{i}", n)
        salt = det(f"{V.name}s{i}", sw) if i % 4 in (0, 1, 3) else b""
        per = det(f"{V.name}p{i}", sw) if i % 4 in (1, 2, 3) else b""
        key = det(f"{V.name}sk{i}", min(mx, 1 + i * 3)) if i % 2 else b""
        ol = mx if i % 3 else mx // 2
        rows.append((msg, key, salt, per, ol,
                     hf(msg, key=key, salt=salt, person=per, digest_size=ol).digest()))
    return rows

def emit_digest(f, V, rows):
    p = V.name
    f.append(f"// message, key, salt, personalisation, digest — the digest length is the digest's.\n")
    f.append(f"fn rows_{p}() -> [[Str]]\n    [\n")
    f.append(",\n".join("        [" + ", ".join(q(x) for x in (m, k, s, pe, d)) + "]" for m, k, s, pe, _, d in rows))
    f.append("\n    ]\n\n")

def inter_rows(V):
    w = V.w
    rows = []
    for i in range(10):
        h = [rng.getrandbits(w) for _ in range(8)]
        m = [rng.getrandbits(w) for _ in range(16)]
        if i == 0:
            h = list(V.iv); m = [0] * 16
        if i == 1:
            h = [V.M] * 8; m = [V.M] * 16
        t = rng.getrandbits(w if i % 2 else 2 * w - 3) if i > 1 else (V.block if i == 1 else 0)
        last = i % 3 != 0
        node = i % 4 == 3
        f0 = V.M if last else 0
        f1 = V.M if node else 0
        v = V.work(h, t, f0, f1)
        r = i % V.rounds
        after_round = V.rnd(v, m, r)
        out = V.compress(h, m, t, f0, f1)
        flat = (h + m + [t & V.M, (t >> w) & V.M, 1 if last else 0, 1 if node else 0]
                + v + [r] + after_round + out)
        rows.append([x if idx in (26, 27, 44) else sgn(x, w) for idx, x in enumerate(flat)])
    return rows

def g_rows(V):
    w = V.w
    rows = []
    lanes = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
             (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
    for i in range(16):
        v = [rng.getrandbits(w) for _ in range(16)]
        a, b, c, d = lanes[i % 8]
        x, y = rng.getrandbits(w), rng.getrandbits(w)
        out = V.g(v, a, b, c, d, x, y)
        rows.append([sgn(t, w) for t in v] + [a, b, c, d] + [sgn(x, w), sgn(y, w)] + [sgn(t, w) for t in out])
    return rows

def param_rows(V):
    rows = []
    sw = 16 if V is B else 8
    for i in range(14):
        p = dict(digest_length=rng.randint(1, 64 if V is B else 32), key_length=rng.randint(0, 64 if V is B else 32),
                 fanout=rng.randint(0, 255), depth=rng.randint(0, 255), leaf_length=rng.getrandbits(32),
                 node_offset=rng.getrandbits(64 if V is B else 48), node_depth=rng.randint(0, 255),
                 inner_length=rng.randint(0, 255), salt=det(f"ps{i}", sw), personal=det(f"pp{i}", sw))
        if i == 0:
            p.update(digest_length=32, key_length=0, fanout=1, depth=1, leaf_length=0, node_offset=0,
                     node_depth=0, inner_length=0, salt=bytes(sw), personal=bytes(sw))
        blk = V.param_block(p)
        n = V.w // 8
        words = [sgn(int.from_bytes(blk[j * n:(j + 1) * n], "little"), V.w) for j in range(8)]
        salt_lo = int.from_bytes(p["salt"][:8], "little"); salt_hi = int.from_bytes(p["salt"][8:16], "little")
        per_lo = int.from_bytes(p["personal"][:8], "little"); per_hi = int.from_bytes(p["personal"][8:16], "little")
        rows.append([p["digest_length"], p["key_length"], p["fanout"], p["depth"], sgn(p["leaf_length"], 64),
                     sgn(p["node_offset"], 64), p["node_depth"], p["inner_length"],
                     sgn(salt_lo, 64), sgn(salt_hi, 64), sgn(per_lo, 64), sgn(per_hi, 64)] + words)
    return rows

def emit_ints(f, name, rows, doc):
    f.append(f"// {doc}\nfn {name}() -> [[Int]]\n    [\n")
    f.append(",\n".join("        [" + ", ".join(str(x) for x in r) + "]" for r in rows))
    f.append("\n    ]\n\n")

def main():
    f = ["""// generated_vectors_tests.nv — expected values produced by vectors/generate.py.
//
// Do not edit by hand: run `python3 -I generate.py` in tests/vectors.  The
// digests come from CPython's hashlib (blake2b, blake2s); the parameter-block
// words, G, the round and the compression function come from the pure-Python
// reference in rfc_check.py, which asserts on import that it agrees with
// hashlib at every length around a block boundary.

use std.bytes
use std.test
use b2err
use b2param
use b2bytes
use blake2b
use blake2s

fn hex(s: Str) -> Bytes
    bytes.from_hex(s) ?? bytes.zeros(0)

"""]
    emit_digest(f, B, digest_rows(B, hashlib.blake2b))
    emit_digest(f, S, digest_rows(S, hashlib.blake2s))
    emit_ints(f, "inter_b", inter_rows(B), "h[8], m[16], t0, t1, last, last_node, work[16], round r, after_round[16], compress[8]")
    emit_ints(f, "inter_s", inter_rows(S), "h[8], m[16], t0, t1, last, last_node, work[16], round r, after_round[16], compress[8]")
    emit_ints(f, "g_b", g_rows(B), "v[16], a, b, c, d, x, y, out[16]")
    emit_ints(f, "g_s", g_rows(S), "v[16], a, b, c, d, x, y, out[16]")
    emit_ints(f, "param_b", param_rows(B), "the twelve fields, then the eight words of the block")
    emit_ints(f, "param_s", param_rows(S), "the twelve fields, then the eight words of the block")
    f.append(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_tail.nv.in")).read())
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "generated_vectors_tests.nv")
    open(out, "w").write("".join(f))
    # Leave the file in the formatter's canonical layout.
    subprocess.run(["novo", "fmt", out], check=True, stdout=subprocess.DEVNULL)

main()
