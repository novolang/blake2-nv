# A pure-Python BLAKE2b and BLAKE2s written from RFC 7693, used to produce the
# intermediate values (parameter-block words, G, a round, F) that hashlib does
# not expose.  Every digest it makes is checked against hashlib on import, so
# a mistake here fails before any vector is emitted.  Run with
# `python3 -I rfc_check.py` to see the check.
import hashlib, struct

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

class Variant:
    def __init__(self, name):
        if name == "b":
            self.w, self.rounds, self.R = 64, 12, (32, 24, 16, 63)
            self.iv = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                       0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
            self.block = 128
        else:
            self.w, self.rounds, self.R = 32, 10, (16, 12, 8, 7)
            self.iv = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
            self.block = 64
        self.M = (1 << self.w) - 1
        self.name = name

    def rotr(self, x, n):
        return ((x >> n) | (x << (self.w - n))) & self.M

    def g(self, v, a, b, c, d, x, y):
        M, R = self.M, self.R
        v = list(v)
        v[a] = (v[a] + v[b] + x) & M
        v[d] = self.rotr(v[d] ^ v[a], R[0])
        v[c] = (v[c] + v[d]) & M
        v[b] = self.rotr(v[b] ^ v[c], R[1])
        v[a] = (v[a] + v[b] + y) & M
        v[d] = self.rotr(v[d] ^ v[a], R[2])
        v[c] = (v[c] + v[d]) & M
        v[b] = self.rotr(v[b] ^ v[c], R[3])
        return v

    def work(self, h, t, f0, f1):
        v = list(h) + list(self.iv)
        v[12] ^= t & self.M
        v[13] ^= (t >> self.w) & self.M
        v[14] ^= f0
        v[15] ^= f1
        return v

    def rnd(self, v, m, r):
        s = SIGMA[r % 10]
        v = self.g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        v = self.g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        v = self.g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        v = self.g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        v = self.g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        v = self.g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        v = self.g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        v = self.g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        return v

    def compress(self, h, m, t, f0, f1):
        v = self.work(h, t, f0, f1)
        for r in range(self.rounds):
            v = self.rnd(v, m, r)
        return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]

    def words(self, data):
        n = self.w // 8
        data = data.ljust(self.block, b"\0")
        return [int.from_bytes(data[i * n:(i + 1) * n], "little") for i in range(self.block // n)]

    def param_block(self, p):
        # p: dict of the twelve logical fields.  Packed with struct, from the
        # byte layout of RFC 7693 section 2.5, independent of the Novo code.
        if self.name == "b":
            blk = struct.pack("<BBBBI Q BB 14x 16s 16s", p["digest_length"], p["key_length"], p["fanout"],
                              p["depth"], p["leaf_length"], p["node_offset"], p["node_depth"],
                              p["inner_length"], p["salt"], p["personal"])
        else:
            blk = struct.pack("<BBBBI 6s BB 8s 8s", p["digest_length"], p["key_length"], p["fanout"],
                              p["depth"], p["leaf_length"], p["node_offset"].to_bytes(6, "little"),
                              p["node_depth"], p["inner_length"], p["salt"], p["personal"])
        return blk

    def hash(self, msg, key=b"", salt=b"", person=b"", outlen=None):
        outlen = outlen or (64 if self.name == "b" else 32)
        p = dict(digest_length=outlen, key_length=len(key), fanout=1, depth=1, leaf_length=0,
                 node_offset=0, node_depth=0, inner_length=0, salt=salt, personal=person)
        pw = self.words(self.param_block(p)) if False else None
        n = self.w // 8
        blk = self.param_block(p)
        h = [self.iv[i] ^ int.from_bytes(blk[i * n:(i + 1) * n], "little") for i in range(8)]
        data = (key.ljust(self.block, b"\0") if key else b"") + msg
        if not data:
            data = b""
        blocks = [data[i:i + self.block] for i in range(0, len(data), self.block)] or [b""]
        t = 0
        for i, b in enumerate(blocks):
            last = i == len(blocks) - 1
            t += len(b)
            h = self.compress(h, self.words(b), t, self.M if last else 0, 0)
        out = b"".join(x.to_bytes(n, "little") for x in h)
        return out[:outlen]

B, S = Variant("b"), Variant("s")

def check():
    import os
    for V, hf in ((B, hashlib.blake2b), (S, hashlib.blake2s)):
        mx = 64 if V is B else 32
        sw = 16 if V is B else 8
        for n in (0, 1, 3, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300):
            msg = bytes(range(256)) * 2
            msg = msg[:n]
            for key in (b"", b"k", bytes(range(mx))):
                for ol in (1, 16, mx):
                    assert V.hash(msg, key, outlen=ol) == hf(msg, key=key, digest_size=ol).digest(), (V.name, n, len(key), ol)
        assert V.hash(b"m", b"", b"S" * sw, b"P" * sw, 20) == hf(b"m", salt=b"S" * sw, person=b"P" * sw, digest_size=20).digest()
check()

if __name__ == "__main__":
    print("rfc_check: the reference agrees with hashlib")
