# Changelog

All notable changes to blake2-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.0.1 — 2026-09-12

The **interface**: every signature and every effect row, and no bodies.
`stability = "draft"`, and the release is recorded `implemented = false`.

### Added

- `b2param` — RFC 7693 § 2.8's parameter block as a twelve-field
  `@value`, the five builders, the twelve accessors, and the two
  serialisations (`b_word`, `s_word`) that let one type describe both
  algorithms' differently-shaped blocks.
- `blake2b` — `B2bState` and `B2bWork`, the IV, σ and the four
  rotations, the G function, the round, the compression function, and
  a whole streaming hash in `feed_byte` / `finish` / `digest_byte`
  with no `Bytes` in the module.
- `blake2s` — the same surface at 32-bit words, ten rounds and a
  64-byte block, with `mask` as the operation BLAKE2b does not need.
- `b2bytes` — the bridge: ten width checks answering `?B2Error`, two
  parameter builders, the little-endian word readers, the keyed
  initialisers that feed the key's padded block, feed-and-finish over
  `Bytes`, and six one-shots.
- `b2err` — one error type, an `Error` impl, and the predicate that
  tells a caller's width mistake from a mode this package declines to
  drive.

### Known

- **The load-bearing interface is that the parameter block is a
  value.**  Plain, keyed, salted, personalised and tree BLAKE2 are one
  initialiser over five parameter blocks, not five entry points.
- **The digest length is the output buffer's length** in every
  `b2bytes` function, because BLAKE2b-256 is not BLAKE2b-512 truncated
  and a signature with two numbers cannot detect the disagreement.
- **A keyed hash compresses the key's padded block**, so a keyed hash
  of the empty message is not the unkeyed one; the keyed vectors over
  an empty message are in the suite for that reason.
- **BLAKE2 buffers lazily** and `feed_byte` is that rule: a full block
  is compressed when the next byte arrives, never when it fills.
- **The device claim covers `b2param`, `blake2b` and `blake2s`**, and
  what it covers is a WHOLE hash — `tests/embedded_probe.nv` builds it
  for a Cortex-M4.  `b2bytes` speaks `Bytes` and is the host's half.
- **No dependencies**, deliberately: the IVs are sixteen constants, and
  the constant-time comparison a MAC verification needs is crypto-nv's
  `digest.ct_eq`, named in the README rather than duplicated here.
- **crypto-nv 0.1.2 ships no BLAKE3**, and BLAKE3 could not substitute
  for this anyway — a different compression function, an always-on
  tree, and keying through the IV rather than a first block.
- BLAKE2bp, BLAKE2sp, driven tree hashing and BLAKE2X are deliberately
  outside, with `b2param.with_tree` published so a caller can drive
  them.
