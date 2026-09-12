# blake2-nv

BLAKE2 is a cryptographic hash function, specified in
[RFC 7693](https://www.rfc-editor.org/rfc/rfc7693). This package brings it to
novo-lang. Two other packages on the registry are defined in terms of it:
[argon2-nv](https://novo-lang.org/packages/argon2-nv) (the password hash
Argon2 is built on BLAKE2b) and
[paseto-nv](https://novo-lang.org/packages/paseto-nv) (PASETO v4 tokens use
BLAKE2b as their message authentication code).

**Status: NOT IMPLEMENTED — interface only.** Every function is declared with
its full signature, but every body is a `todo()` that panics when called. The
package is published so its design can be reviewed and depended on before it
is implemented. Version 0.1.0 will be the first working release.

## What BLAKE2 is

In the words of RFC 7693, BLAKE2 comes in two basic flavours:

- **BLAKE2b** is optimized for 64-bit platforms and produces digests of any
  size between 1 and 64 bytes.
- **BLAKE2s** is optimized for 8- to 32-bit platforms and produces digests of
  any size between 1 and 32 bytes.

Both flavours can take an optional secret key. A keyed BLAKE2 is a message
authentication code (MAC) in its own right; unlike SHA-2, it does not need
the HMAC construction wrapped around it. Both also accept an optional salt
and an optional personalization string, which make the hash unique to one
application.

## Install

```
novo pkg add blake2-nv
```

## Example

```novo
use std.bytes
use b2bytes

fn main() [io]
    // The BLAKE2b-512 digest of "abc" (RFC 7693, Appendix A).
    // The digest length is the length of the output buffer: 64 bytes here.
    match b2bytes.blake2b_into(bytes.from_str("abc"), bytes.zeros(64))
        Ok(d)  => println(bytes.to_hex(d))
        Err(e) => println("refused")

    // The same function family as a MAC: a keyed BLAKE2b with a 32-byte
    // key and a 32-byte tag. This is how PASETO v4 authenticates a token.
    match b2bytes.blake2b_keyed_into(bytes.zeros(32), bytes.from_str("abc"), bytes.zeros(32))
        Ok(t)  => println(bytes.to_hex(t))
        Err(e) => println("refused")
```

Build and test with:

```
novo pkg build
novo test
```

Today `novo test` fails on purpose: every test reaches a
`not implemented: blake2-nv.<module>.<fn>` panic. The tests are the
specification the implementation will have to satisfy.

## What the package contains

| Module | Contents |
| --- | --- |
| `b2bytes` | The functions most programs will call. They take `Bytes` in and write the digest into a buffer you supply. One-shot hashing, keyed hashing, and a streaming form (`init`, `update`, `finish`). |
| `blake2b` | BLAKE2b at the lowest level: the hash state as a plain value, the compression function, and a byte-at-a-time streaming interface. Uses no heap memory. |
| `blake2s` | The same for BLAKE2s. |
| `b2param` | The BLAKE2 parameter block (RFC 7693, section 2.8): digest length, key length, salt, personalization and the tree-hashing fields, as a value you build before hashing. |
| `b2err` | The error type. Every error means a length was wrong: a digest, key, salt or personalization longer than the flavour allows, or a buffer that does not match the requested digest length. |

## How to choose an entry point

**Most programs use `b2bytes`.** Give it the input as `Bytes` and an output
buffer whose length is the digest length you want. For a keyed hash, pass
the key as well. The streaming form lets you feed the input in pieces when
it does not all fit in memory at once.

**Firmware uses `blake2b` or `blake2s` directly.** These two modules use no
`Bytes`, no strings and no lists. A hash state is a small value that lives
on the caller's own stack: 224 bytes for BLAKE2b, 160 bytes for BLAKE2s. You
feed the message one byte at a time with `feed_byte`, call `finish`, and read
the digest out with `digest_byte`. Nothing is allocated from start to end,
which is what lets a bootloader hash an image in flash on a microcontroller
with no heap. See "Running on a microcontroller" below.

`b2bytes` is written on top of the two low-level modules, so the two paths
always agree.

## Parameters: digest length, key, salt, personalization

BLAKE2 has a single construction. Plain, keyed, salted and personalized
hashing are not different algorithms; they are the same algorithm started
from different values of one 64-byte (BLAKE2b) or 32-byte (BLAKE2s)
*parameter block*, described in RFC 7693 section 2.8. `b2param` builds that
block: `sequential(digest_len)` for a plain hash, `keyed(digest_len,
key_len)` for a MAC, and `with_salt`, `with_personal` and
`with_digest_length` to adjust one. `keyed(n, 0)` produces exactly the same
block as `sequential(n)`, so code whose key is optional does not need two
paths.

Two consequences of this design are worth knowing, because they are the
two things a hand-written BLAKE2 most often gets wrong:

1. **The digest length is part of the hash.** It is the first byte of the
   parameter block and is mixed into the initial state before any input is
   read. A 32-byte BLAKE2b digest is therefore *not* the first 32 bytes of the
   64-byte digest of the same input; the two share nothing. That is why every
   function in `b2bytes` takes the digest length from the length of the
   output buffer you pass, and never as a separate number that could
   disagree with it.
2. **The key is also the first block of the message.** RFC 7693 section 3.3
   places the key, padded to a full block, in front of the input. So a keyed
   hash of an *empty* message still processes one block. An implementation
   that records the key length but skips that block computes a value nothing
   else in the world computes. The test suite includes keyed hashes of the
   empty message at both widths for exactly this reason.

## Running on a microcontroller

novo-lang lets a package state which of its modules can run on a device
with no heap allocator, and the registry checks that claim by compiling a
probe program for a Cortex-M4. For this package the claim covers `b2param`,
`blake2b`, `blake2s` and `b2err`. These modules contain only integer
arithmetic over fixed-size values, so they build and run on that target. The
`b2bytes` module is excluded from the claim because `Bytes` and `Result` are
heap objects; it is meant for programs with an operating system underneath.

One detail of the low-level interface matters for correctness. BLAKE2
finalizes the *last* block with a flag set, so an implementation must not
compress a buffer merely because it is full: it has to wait for the next
byte to learn whether that buffer was the last one. `feed_byte` implements
this rule. An implementation that compresses eagerly gives wrong answers on
exactly those inputs whose length is a multiple of the block size, and right
answers on every other input.

## Timing behaviour

For a cryptographic package it matters which operations take the same time
regardless of the data they process.

- The core functions `g`, `round` and `compress` are constant-time by
  construction. They use only addition, XOR and rotation by fixed amounts.
  No branch depends on a key bit and no table is indexed by secret data.
- The streaming functions (`feed_byte`, `update_b`, `update_s`) branch on how
  many bytes are buffered, that is, on the message length. In both
  constructions this package exists for, Argon2 and PASETO v4, message
  lengths are public.
- The accessors `state_word`, `block_word`, `block_byte` and `digest_byte`
  are indexed by an argument the caller chooses. They are constant-time with
  respect to the key, not with respect to that index. Nothing in this package
  passes a secret as an index.
- **This package does not compare digests.** Checking a MAC needs a
  constant-time comparison, and the one on the registry is
  `digest.ct_eq` in [crypto-nv](https://novo-lang.org/packages/crypto-nv). A
  program that verifies a tag calls that function itself. blake2-nv does not
  depend on crypto-nv, so that a device which only needs a hash does not
  have to link crypto-nv as well.

## What is not included

- **BLAKE2bp and BLAKE2sp**, the parallel variants. Each is a fixed
  four-way or eight-way tree with its own test vectors. `b2param.with_tree`
  can build the parameter blocks they need, so a program can construct them
  from `blake2b` if it must, but the package does not ship them.
- **Tree hashing in general.** The parameter block supports it, but the
  one-shot functions refuse a non-sequential parameter block with
  `B2TreeModeNotDriven` rather than hash a single leaf and present it as the
  result. A tree-hashing program drives the leaves and the root itself;
  `mark_last_node` exists for that.
- **BLAKE2X**, the extendable-output variant.
- **A constant-time comparison.** See "Timing behaviour".
- **An HMAC wrapper.** BLAKE2 is keyed directly (RFC 7693, section 1).
  Wrapping it in HMAC would double the cost and add no security.

## Related packages

- [crypto-nv](https://novo-lang.org/packages/crypto-nv) provides SHA-1,
  SHA-256, SHA-512, MD5 and HMAC. As of version 0.1.2 it contains no BLAKE
  function, so this package does not duplicate anything published.
- **BLAKE3** is a different algorithm, not a faster BLAKE2: it has a
  different compression function, an always-on tree mode and an extendable
  output. Neither can be substituted for the other. A program that needs
  BLAKE2b because Argon2 or PASETO specifies it cannot use BLAKE3 instead.
- The initial values (IVs) of BLAKE2b and BLAKE2s are the same constants
  SHA-512 and SHA-256 use. They are written into this package directly rather
  than taken from crypto-nv, so that this package has no dependencies.

## Test vectors

RFC 7693 is the reference. The reference implementation by the algorithm's
authors (`BLAKE2/BLAKE2` on GitHub) supplies the keyed vectors, and
RustCrypto's `blake2` crate is a third check.

The test suite carries:

- RFC 7693 Appendix A: BLAKE2b-512 of `abc`, including the intermediate
  state the appendix prints, so a failing implementation can be bisected.
- RFC 7693 Appendix B: BLAKE2s-256 of `abc`.
- The digest of the empty input, at both widths.
- Entry 0 of `blake2-kat.json` at both widths: the keyed hash of an empty
  message under the key `00 01 … 3f` (BLAKE2b) and `00 01 … 1f` (BLAKE2s).
  This is the case that fails when the key's padded block is skipped.
- The IVs, the sigma permutation table (including rounds 10 and 11, which
  reuse rows 0 and 1), and the four rotation constants, each asserted
  against the RFC's own numbers, so a failing assertion names the paragraph
  it disagrees with.

An implementation note: five of BLAKE2b's eight IV words have their top bit
set. novo-lang's `Int` is signed, so those words cannot be written as
hexadecimal literals; `0xBB67AE8584CAA73B` appears in the source as
`-4942790177534073029`. crypto-nv's SHA-512 writes the same five constants
the same way.

## Implementation status

| Item | Implemented |
| --- | --- |
| The twenty-four `B2*` size constants | yes (they are constants) |
| `b2param.B2Params`, `blake2b.B2bState`, `.B2bWork`, `blake2s.B2sState`, `.B2sWork`, `b2err.B2Error` | declared |
| `b2param.sequential`, `.keyed`, `.with_salt`, `.with_personal`, `.with_tree`, `.with_digest_length` | no |
| `b2param`'s twelve accessors, `.is_sequential`, `.b_word`, `.s_word`, `.check_b`, `.check_s` | no |
| `blake2b.iv`, `.sigma`, `.rotation`, `.rotr` | no |
| `blake2b.init`, `.zero_state` and the state accessors | no |
| `blake2b.work`, `.g`, `.round`, `.compress` | no |
| `blake2b.feed_byte`, `.finish`, `.digest_byte` | no |
| The same twenty-one functions on `blake2s`, plus `.mask` | no |
| `b2bytes`'s ten length checks and two parameter builders | no |
| `b2bytes.init_keyed_b`, `.init_keyed_s`, the four updates, the two finishes | no |
| `b2bytes`'s six one-shot functions | no |
| `b2err.describe`, `.is_width_fault`, `B2Error.message` | no |

## Licence

Apache-2.0. See `LICENSE`.
