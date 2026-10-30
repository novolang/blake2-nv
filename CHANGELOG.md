# Changelog

All notable changes to blake2-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0 — 2026-10-29

BLAKE2b and BLAKE2s (RFC 7693), plain and keyed, with the salt, the
personalization and the digest length as a parameter block.
`stability = "experimental"` and the toolchain floor is `novo >= 0.22.0`.

### Added

- `blake2b` and `blake2s`: the state, the compression function, the rounds,
  G, `init`, `feed_byte`, `finish` and `digest_byte`, held in `@value`
  structs at `@tier(embedded)`.
- `b2param`: the parameter block as twelve integers, its builders and its
  serialization to the eight words of each algorithm.
- `b2bytes`: the width checks, `params_b` and `params_s`, `init_keyed_b` and
  `init_keyed_s`, `update_b`, `update_range_b` and their BLAKE2s forms,
  `finish_into_b` and `finish_into_s`, and the one-shots `blake2b_into`,
  `blake2b_keyed_into`, `blake2b_full_into` and their BLAKE2s forms.
- `b2err`: the messages of `B2Error` and `is_width_fault`.
- `host_modules` in the manifest names `b2bytes` and `b2err`, so the device
  build covers `blake2b`, `blake2s` and `b2param`.
- Tests against RFC 7693 appendices A, B and E, against Python's `hashlib`
  for digests of every length, key, salt and personalization, and against a
  reference in `tests/vectors/rfc_check.py` for the parameter block, G, a
  round and the compression function.

### Changed

- `check_b` and `check_s` moved from `b2param` to `b2bytes`. `B2Error`
  carries numbers, which a device cannot build, and the device build copies
  every module that is not a host module, so a check in `b2param` kept the
  module off the device. The signatures are unchanged.
- `blake2b_full_into` and `blake2s_full_into` replace the `key_length` field
  of the block they are given with the length of the key, so a block made by
  `b2param.sequential` and a key is a keyed hash.

### Clarified

- The functions that fill a caller's `out` buffer (`finish_into_b`,
  `finish_into_s` and the one-shots) answer a copy; `out` is not modified.
- `finish_into_b` accepts an `out` longer than the digest length and answers
  the prefix.
- The accessors that take an index answer `0` for an index out of range, and
  the setters return the value unchanged.
- A state is 240 bytes for both algorithms: every field is an eight-byte
  `Int`, whatever the width of the word it carries.
