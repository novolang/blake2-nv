# blake2-nv

BLAKE2 is a family of cryptographic hash functions specified in
[RFC 7693](https://www.rfc-editor.org/rfc/rfc7693). BLAKE2b is optimised for
64-bit platforms and produces digests of any size between 1 and 64 bytes.
BLAKE2s is optimised for 8- to 32-bit platforms and produces digests of any
size between 1 and 32 bytes. This package brings both to novo-lang, with the
keyed mode, the salt and the personalization of the specification.

## What BLAKE2 is

A *hash function* turns a message of any length into a short, fixed-size
*digest*. Two different messages give two different digests in practice, and
the message cannot be recovered from the digest.

BLAKE2 mixes sixteen words with addition, XOR and rotation. BLAKE2b works on
64-bit words and twelve rounds of mixing, and takes a 128-byte block. BLAKE2s
works on 32-bit words and ten rounds, and takes a 64-byte block.

A *message authentication code* (MAC) is a short value that proves a message
was made by someone who holds a secret key. BLAKE2 can be keyed directly
(RFC 7693 section 1), so a keyed hash is a MAC and no HMAC construction is
needed. A key is at most 64 bytes for BLAKE2b and 32 bytes for BLAKE2s.

The *parameter block* is a 64-byte header for BLAKE2b and a 32-byte header for
BLAKE2s. It fixes the digest length, the key length, the salt, the
personalization and the tree-hashing fields. The initial state of the hash is
the initialization vector XOR the parameter block (RFC 7693 section 2.5). The
*salt* and the *personalization* are 16 bytes for BLAKE2b and 8 bytes for
BLAKE2s. Two protocols that use the same key and different personalizations
compute different MACs.

| Value | BLAKE2b | BLAKE2s |
| --- | --- | --- |
| Word | 64 bits | 32 bits |
| Block | 128 bytes | 64 bytes |
| Rounds | 12 | 10 |
| Digest | 1 to 64 bytes | 1 to 32 bytes |
| Key | 0 to 64 bytes | 0 to 32 bytes |
| Salt | 16 bytes | 8 bytes |
| Personalization | 16 bytes | 8 bytes |

## Install

```
novo pkg add blake2-nv
```

## Example

```novo
use std.bytes
use b2bytes

fn tag(key: Bytes, message: Bytes) -> Result<Bytes, B2Error>
    // The length of the buffer is the length of the digest.
    b2bytes.blake2b_keyed_into(key, message, bytes.zeros(32))
```

`blake2b_keyed_into` answers a 32-byte MAC. Compare two MACs with a
constant-time comparison such as `digest.ct_eq` of crypto-nv, not with `==`.

Build and test with:

```
novo pkg build
novo test
```

## What the package contains

| Module | Contents | Builds for a microcontroller |
| --- | --- | --- |
| `blake2b` | BLAKE2b as a state held in the caller's frame: `init`, `feed_byte`, `finish` and `digest_byte`, and under them the compression function, the rounds and G. | yes |
| `blake2s` | The same for BLAKE2s. | yes |
| `b2param` | The parameter block as twelve integers, its builders, and its serialization to the eight words of each algorithm. | yes |
| `b2bytes` | The boundary with `Bytes`: width checks, keyed initialization, updating from a buffer, and the one-shot functions that write a digest into a buffer. | no |
| `b2err` | The error type `B2Error`, its messages, and `is_width_fault`. | no |

## How to choose an entry point

**Most programs call `b2bytes.blake2b_into`** to hash a message, and
**`b2bytes.blake2b_keyed_into`** to authenticate one. The length of the `out`
buffer is the digest length.

**Call `blake2s_into` and `blake2s_keyed_into`** when a protocol specifies
BLAKE2s, as Noise and WireGuard do.

**Call `blake2b_full_into` or `blake2s_full_into`** for a salt or a
personalization. Build the parameter block with `b2bytes.params_b` and
`b2bytes.params_s`, or with `b2param.with_salt` and `b2param.with_personal`.

**Call `update_b`, `update_range_b` and `finish_into_b`** to hash a message
that arrives in pieces. Start the state with `blake2b.init`, or with
`b2bytes.init_keyed_b` for a keyed hash. `update_range_b` hashes part of a
buffer without copying it.

**Firmware calls `blake2b.feed_byte` and `blake2b.finish`** directly. See
"Running on a microcontroller".

## The rules a user needs

1. **The digest length is part of the hash.** BLAKE2b with a 32-byte digest is
   not the first 32 bytes of BLAKE2b with a 64-byte digest. The two share no
   prefix, because the length is written into the initial state (RFC 7693
   section 2.5). For that reason the length of the `out` buffer is the digest
   length in every one-shot, and there is no second number to disagree with it.
2. **A keyed hash of an empty message is not an unkeyed hash.** The key,
   padded with zeros to a full block, is hashed as the first block (RFC 7693
   section 3.3). `b2bytes.init_keyed_b` and `init_keyed_s` do this. A state
   made with `blake2b.init` alone does not absorb a key.
3. **An empty key is the unkeyed mode.** It is not an error.
4. **The key is the key's length.** `blake2b_full_into` replaces the
   `key_length` field of the block it is given with the length of the key.
5. **Salt and personalization have exactly one width or are empty.**
   `check_salt_b` and `check_personal_b` refuse any other length. A short salt
   is not padded.
6. **Tree hashing is not driven.** The parameter block can hold the tree
   fields. `blake2b_full_into` refuses a block whose fanout is not 1, whose
   depth is not 1, or whose leaf length, node offset, node depth or inner
   length is not 0, with `B2TreeModeNotDriven`. A caller that builds BLAKE2bp
   or a Merkle mode drives `blake2b.compress`, `mark_last` and
   `mark_last_node` itself.
7. **The functions that fill a buffer answer a copy.** `finish_into_b` and
   the one-shots write the digest at offset 0 of a copy of `out` and answer
   the first `digest_length` bytes of that copy. `out` is not modified. An
   `out` longer than the digest length is accepted by `finish_into_b`.
8. **The width checks are separate functions.** `check_digest_length_b`,
   `check_key_b`, `check_salt_b`, `check_personal_b`, `check_inputs_b` and
   `check_b` each answer `?B2Error`. The one-shots perform them. `params_b`,
   `params_s`, `init_keyed_b` and `init_keyed_s` do not refuse: they read
   what they are given, and a byte past the end of a buffer reads as zero.
9. **BLAKE2 is lazy about the last block.** A full block is compressed only
   when the next byte arrives, because the last block carries the final flag.
   `feed_byte` does this, and `buffered` is 128 (BLAKE2b) or 64 (BLAKE2s)
   after a message that fills a block exactly.

## Running on a microcontroller

novo-lang lets a package state which of its modules run on a device with no
heap allocator, and the registry checks that claim by compiling a probe
program for a Cortex-M4. Here the claim covers `blake2b`, `blake2s` and `b2param`.

A hash in flight is a plain value struct of 240 bytes in the caller's own
stack frame, holding the chaining value, the block being filled, the byte
counter and the two flags. The block is sixteen words inside the state, not a
buffer, so a bootloader that checks an image in flash reads a byte, calls
`feed_byte`, and compares the digest at the end with the heap untouched.
`tests/embedded_probe.nv` builds both hashes for the device, and the probe was
run under QEMU and answered the RFC 7693 digests of "abc".

`b2param` holds the parameter block as twelve integers and uses no heap
either; the two hashes call it. The width checks that refuse a block, `check_b`
and `check_s`, are in `b2bytes`, because the error they answer carries numbers.
The registry shows the microcontroller tier for `blake2b`, `blake2s` and
`b2param`, and not for `b2bytes` and `b2err`, which the manifest names as host
modules.

## Timing behaviour

The limits of each claim are stated here exactly. They describe the source.
The compiler makes no promise about the machine code, and nothing here has
been measured on a target.

**Constant time with respect to the key and the message, by construction.**
`g`, `round` and `compress` use addition, XOR and rotation by constant
amounts. No branch depends on a key bit, no table is read at a data-dependent
index, and the message-word order σ is selected by the round number alone.

**Not constant time with respect to the message length.** `feed_byte` and
`finish` branch on the number of bytes buffered. The message length is not
secret in the uses of BLAKE2 as a MAC or as a hash.

**Not constant time with respect to an index the caller chooses.**
`state_word`, `block_word`, `block_byte` and `digest_byte` index an array with
the argument they are given. Do not pass a secret as that argument.

**This package compares nothing.** Compare two MACs with `digest.ct_eq` from
crypto-nv, which takes the same time whatever the position of the first
difference.

## What is not included

- **Tree hashing** (BLAKE2bp, BLAKE2sp, Merkle modes). The parameter block
  carries the fields and `mark_last_node` sets the flag. A caller supplies the
  leaf and node schedule.
- **Variable-length output above 64 bytes** (BLAKE2X). Argon2 builds its
  variable-length hash from `blake2b_into` at lengths up to 64.
- **HMAC and HKDF over BLAKE2.** A keyed BLAKE2 is already a MAC.
- **A constant-time comparison.** Use `digest.ct_eq` from crypto-nv.

## Related packages

[crypto-nv](https://novo-lang.org/packages/crypto-nv) provides SHA-2, SHA-3,
HMAC and `digest.ct_eq`, the constant-time comparison for a MAC.
[chacha20-nv](https://novo-lang.org/packages/chacha20-nv) provides the stream
cipher of RFC 8439 and XChaCha20-Poly1305.

## Test vectors

`tests/blake2_tests.nv` holds the digests of RFC 7693 appendix A (BLAKE2b-512
of "abc") and appendix B (BLAKE2s-256 of "abc"), and the self-test of
appendix E, which hashes inputs of six lengths at four digest lengths, keyed
and unkeyed, and folds all the digests into one. Both published results are
reproduced.

`tests/generated_vectors_tests.nv` is written by `tests/vectors/generate.py`.
Its digests come from Python's `hashlib` and cover lengths around each block
boundary, every digest length, every key length, and salts and
personalizations. Its parameter-block words, G, round and compression values
come from a reference in `tests/vectors/rfc_check.py` that is checked against
`hashlib` when it is loaded.

`tests/blake2_edge_tests.nv` covers every accessor, every refusal and every
out-of-range read.

## Licence

Apache-2.0.
