# blake2-nv

RFC 7693's BLAKE2b and BLAKE2s for novo-lang: the hash Argon2 is
defined over, the MAC PASETO v4 is defined over, and the one a device
can run out of its own stack frame.

**Status: NOT IMPLEMENTED — interface only.**

Every `pub fn` body is a `todo()`.  The signatures, the effect rows and
the types are published so the design can be reviewed and depended on
before anyone writes a compression function; the first implementation
is the `0.1.0` published over this.

## What this is

BLAKE2 is one algorithm in two widths.  **BLAKE2b** works on 64-bit
words, compresses 128 bytes at a time in twelve rounds, and produces 1
to 64 bytes of digest.  **BLAKE2s** works on 32-bit words, compresses
64 bytes in ten rounds, and produces 1 to 32.  Both take an optional
key — which makes them a MAC with no HMAC wrapper around them — and an
optional salt and personalisation.

This package publishes:

| module | what it is | in the device claim |
| --- | --- | --- |
| `b2param` | RFC 7693 § 2.8's parameter block, as a value | yes |
| `blake2b` | the 64-bit state, compression function and streaming hash | yes |
| `blake2s` | the 32-bit state, compression function and streaming hash | yes |
| `b2bytes` | the bridge: `Bytes` in, a caller's buffer out | no |
| `b2err` | one error type, every arm a caller's width mistake | yes |

Two packages already on the grid are blocked on it.  **argon2-nv**'s
README says BLAKE2b is the primitive its whole surface is defined over
and that nothing on the registry publishes one.  **paseto-nv** says the
same from the other direction: `v4.local`'s key splitting, its MAC and
every PASERK identifier are BLAKE2b.  Two packages finding the same gap
from opposite ends is the argument for one row rather than two copies.

## Install

```
novo pkg add blake2-nv
```

## The one example that will work

```novo
use std.bytes
use b2bytes

fn main() [io]
    // BLAKE2b-512 of "abc" — RFC 7693 Appendix A.
    match b2bytes.blake2b_into(bytes.from_str("abc"), bytes.zeros(64))
        Ok(d)  => println(bytes.to_hex(d))
        Err(e) => println("refused")

    // The same package as a MAC: keyed BLAKE2b, 32 bytes out.  This is
    // PASETO v4's tag, and there is no HMAC anywhere in it.
    match b2bytes.blake2b_keyed_into(bytes.zeros(32), bytes.from_str("abc"), bytes.zeros(32))
        Ok(t)  => println(bytes.to_hex(t))
        Err(e) => println("refused")
```

Build and test it with:

```
novo pkg build
novo test
```

`novo test` is red today, on purpose: every assertion reaches
`not implemented: blake2-nv.<module>.<fn>`.

## The load-bearing interface: the parameter block is a value

`b2param.B2Params` is the interface the rest of the package hangs from,
and the argument for it is that **BLAKE2 has one construction, not
five.**

RFC 7693 § 2.6 says the initial chaining value is the IV XOR the
parameter block, and § 2.8 says the parameter block holds the digest
length, the key length, the fanout, the depth, the leaf length, the
node offset, the node depth, the inner length, the salt and the
personalisation.  So plain, keyed, salted, personalised and tree BLAKE2
are not five algorithms with five entry points — they are one
initialiser over five parameter blocks.  A package that published
`blake2b`, `blake2b_keyed`, `blake2b_salted` and `blake2b_keyed_salted`
would be publishing the cartesian product of a struct, and the caller
who wanted the combination nobody enumerated would be stuck.

Two consequences follow, and both are the things a port gets wrong:

- **BLAKE2b-256 is not BLAKE2b-512 truncated.**  The digest length is
  byte 0 of the parameter block, so it is XORed into `h[0]` before a
  byte of message is seen.  Two digests of different lengths over the
  same input share no prefix at all.  A port that hashes at 64 and
  truncates passes every 64-byte vector and disagrees with the world
  everywhere else — which is why **every function in `b2bytes` takes
  the digest length as the output buffer's length and offers no second
  number to disagree with it.**
- **The key length is in the parameter block and the key is also a
  message block.**  § 3.3 puts the key, zero-padded to a full block, in
  front of the message — so a keyed hash of the EMPTY message still
  compresses once.  Setting `key_length` and skipping the block
  produces a number nothing else computes.  `b2param.keyed` sets the
  field, `b2bytes.init_keyed_b` feeds the block, and the keyed
  known-answer vectors over an empty message are in the test suite for
  exactly this reason.

One more property of the same decision: `b2param.keyed(n, 0)` is
`b2param.sequential(n)` byte for byte, so a caller whose key is
optional takes one code path and never branches.

## The two halves, and which one a device gets

`blake2b` and `blake2s` take **no `Bytes`, no `Str` and no list at
all**.  A state is eight chaining words and a sixteen-word message
block inside one `@value` — 224 bytes of the caller's own frame for
BLAKE2b, 160 for BLAKE2s — and every function between them is word
algebra.  `tests/embedded_probe.nv` builds them for a Cortex-M4.

What makes the claim worth making is that **the device gets a whole
hash, not a fragment of one**: `init`, `feed_byte`, `finish` and
`digest_byte` are a complete BLAKE2 with no allocator behind them.  A
bootloader verifying an image in flash reads a byte, feeds it, and
compares at the end; the arena is untouched from start to end.

`feed_byte` also carries the rule a port breaks most quietly.  **BLAKE2
buffers lazily**: the last block is compressed with the finalisation
flag set, so a full buffer may never be compressed just because it is
full — the implementation has to wait for another byte and prove the
block was not the last.  A port that compresses eagerly is wrong on
exactly the inputs whose length is a multiple of the block size, and
right on every other one.

`b2bytes` speaks `Bytes` and `Result`, which are heap objects.  It is
the host's half, it is not in the claim, and everything in it is a few
lines over the two modules below it.

## What is constant time, and what is not

A crypto package that does not say is a crypto package a reviewer
cannot use.

- `g`, `round` and `compress` are constant time by construction —
  addition, XOR and rotation by a **constant** amount, no branch on a
  key bit, no table lookup indexed by data.  `sigma` is indexed by the
  round number and the lane, both of which are loop counters.
- `feed_byte`, `update_b` and `update_s` branch on how much is
  buffered, which is a **message length**.  Message lengths are not
  secret in either construction this package exists for: Argon2 and
  PASETO v4 both fix them in advance.
- `state_word`, `block_word`, `block_byte` and `digest_byte` index an
  inline array with an index the **caller** chose.  They are constant
  time with respect to the key; they are not constant time with respect
  to `i`, and nothing in this package passes a secret as `i`.
- **Nothing here compares anything.**  Verifying a MAC is a
  constant-time comparison and the one on the grid is crypto-nv's
  `digest.ct_eq`.  This package does not depend on crypto-nv for it —
  that would put crypto-nv in the link graph of every device that wants
  a hash — so a caller that verifies a tag calls `digest.ct_eq`
  itself.  One implementation of that loop on the grid is the
  arrangement worth having; two would be one too many.

## How it relates to crypto-nv's `blake3` row

crypto-nv's plan row names `blake3` among the primitives it is meant to
carry.  **crypto-nv 0.1.2 does not ship one**: its modules are
`digest`, `hashing`, `md5_core`, `sha1_core`, `sha256_core`,
`sha512_core` and `word`, which is SHA-1, SHA-256, SHA-512, MD5 and
HMAC over each.  So there is no BLAKE of any kind on the registry
today, and this package is not stepping on a published surface.

Nor does it pre-empt the row.  **BLAKE3 is not BLAKE2 with fewer
rounds.**  It has a different compression function, an always-on binary
tree mode with chunk chaining values, an extendable output, and it keys
through the IV rather than through a first message block.  Neither can
be built out of the other, and a program that needs BLAKE2b because
Argon2 or PASETO says so cannot substitute BLAKE3 for it.  When
crypto-nv grows `blake3` the two sit beside each other, and a caller
picks by what their format specifies rather than by which is newer.

## The layer, and why

`core`, and the budget is `[]` throughout.

BLAKE2 is addition, XOR and rotation over sixteen words, plus a
permutation table.  There is no entropy source here, no clock, and
nothing that opens a file: the key, the salt, the personalisation, the
digest length and the message all arrive as arguments.  That is what
lets the same code run in a bootloader and in a password-hashing
server.

**No dependencies.**  The IVs are SHA-512's and SHA-256's, written out
here as constants rather than reached for through crypto-nv, because a
dependency for sixteen numbers would put a package into a device's link
graph for nothing.

## What is outside, and named

- **BLAKE2bp and BLAKE2sp** — the parallel variants.  They are a fixed
  four- or eight-way tree with a defined root, which is a different
  construction with its own vectors, and shipping half of one is worse
  than shipping none.  `b2param.with_tree` builds the parameter blocks
  they need, so a caller who wants one can drive the leaves and the
  root out of `blake2b` directly.
- **Tree hashing in general.**  Same answer: the parameter block is the
  format and this package publishes it, but the one-shots refuse a
  non-sequential block with `B2TreeModeNotDriven` rather than hashing
  the first leaf and calling it the answer.  A tree caller supplies the
  layer walk, the node offsets and the last-node flag; `mark_last_node`
  is here for them.
- **BLAKE2X** — the extendable-output construction over BLAKE2.  It
  needs the tree fields and a defined XOF header, and nothing on the
  grid asks for it yet.
- **A constant-time comparison.**  crypto-nv's `digest.ct_eq`, for the
  reason above.
- **An HMAC wrapper.**  BLAKE2 is keyed directly (§ 1); wrapping it in
  HMAC would double the cost and improve nothing.

## The reference implementation

RFC 7693 is the oracle.  `BLAKE2/BLAKE2` — the reference
implementation by the algorithm's own authors — is the second opinion
and the source of the keyed vectors, and RustCrypto's `blake2` crate is
the third.

The tests carry:

- **RFC 7693 Appendix A** — BLAKE2b-512 of `abc`, with the full
  intermediate state the appendix prints available for a bisect.
- **RFC 7693 Appendix B** — BLAKE2s-256 of `abc`.
- The empty-input digest at both widths, which is the first thing any
  implementation prints.
- **`blake2-kat.json` entry 0 at both widths** — the keyed hash of an
  EMPTY message under the key `00 01 … 3f` (BLAKE2b) and `00 01 … 1f`
  (BLAKE2s).  That case is in the suite rather than optional because it
  is the one that fails when the key's padded block is skipped.
- The IV, the σ table including rounds 10 and 11 reusing rows 0 and 1,
  and the four rotations — each asserted against the specification's
  own numbers, so a failing assertion names the paragraph it disagrees
  with.

**An implementation note the vectors cannot carry**: five of BLAKE2b's
eight IV words have their high bit set, and `Int` is signed, so they
cannot be written as hex literals — `0xBB67AE8584CAA73B` is
`-4942790177534073029` spelled the way the source has to spell it.
crypto-nv's `sha512_core` writes the same five the same way.

## Status

| item | implemented |
| --- | --- |
| the twenty-four `B2*` size constants | yes — they are constants |
| `b2param.B2Params`, `blake2b.B2bState`, `.B2bWork`, `blake2s.B2sState`, `.B2sWork`, `b2err.B2Error` | declared |
| `b2param.sequential`, `.keyed`, `.with_salt`, `.with_personal`, `.with_tree`, `.with_digest_length` | no |
| `b2param`'s twelve accessors, `.is_sequential`, `.b_word`, `.s_word`, `.check_b`, `.check_s` | no |
| `blake2b.iv`, `.sigma`, `.rotation`, `.rotr` | no |
| `blake2b.init`, `.zero_state` and the state accessors | no |
| `blake2b.work`, `.g`, `.round`, `.compress` | no |
| `blake2b.feed_byte`, `.finish`, `.digest_byte` | no |
| the same twenty-one functions on `blake2s`, plus `.mask` | no |
| `b2bytes`'s ten width checks and two parameter builders | no |
| `b2bytes.init_keyed_b`, `.init_keyed_s`, the four updates, the two finishes | no |
| `b2bytes`'s six one-shots | no |
| `b2err.describe`, `.is_width_fault`, `B2Error.message` | no |

## Three more primitives are missing, and none of them is a new package

Three packages staged on 2026-09-12 — tls-nv, acme-nv and keyring-nv —
each named a crypto primitive the registry does not carry.  All three
belong on packages that already exist, so they are recorded here and as
plan notes on those packages rather than staged as rows of their own:

| primitive | where it belongs | why it is not its own package |
| --- | --- | --- |
| **ECDSA sign and verify over P-256** | **p256-nv** | p256-nv 0.0.2 is ECDH-only, and the field arithmetic, the point arithmetic and the key types are already there.  A separate `ecdsa-nv` would duplicate them or depend on p256-nv for all of them.  Without it a TLS client cannot verify the certificate chain of most of the public web. |
| **an AES block cipher, with GCM over it** | **crypto-nv** | crypto-nv's own plan row names AES-GCM and 0.1.2 carries no block cipher, so tls-nv's `suite_is_available` answers false for `TLS_AES_128_GCM_SHA256` — the one suite RFC 8446 § 9.1 makes mandatory.  keyring-nv names AES again for the Secret Service's `dh-ietf1024` session. |
| **SHA-384** | **crypto-nv** | crypto-nv publishes SHA-256 and SHA-512 and nothing between, so tls-nv's `suite_hash` answers `?HkdfHash`.  It is SHA-512's compression function with a different IV and a truncation — a module in the package that already has the compression function, not a package. |

## Licence

Apache-2.0.  See `LICENSE`.
