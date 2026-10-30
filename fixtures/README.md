# Device identity contract fixtures

`device-keys-contract.json` has exactly three sections: `ids`, `keyFiles` and
`relayProof`. Every seed, passphrase, salt, nonce and derived secret is public
deterministic test data. Never use this material for a real identity.

The key-file inputs retain the original seeds, labels, created timestamps,
passphrases, salts, nonces and fixed protection parameters. The current format
is `bubblebuffer-device-key`; its canonical AAD and AES-GCM authentication tag
are regenerated for that identifier. The reader and writer accept only this
format. Wrong-passphrase and tampered-label vectors retain their deliberate
corruption and use the valid protected file's newly sealed ciphertext.

On an authorized build host, regenerate with:

```sh
cargo run --quiet -p bubblebuffer-device-key --example generate_contract > /tmp/device-keys-contract.json
cp /tmp/device-keys-contract.json fixtures/device-keys-contract.json
cargo run --quiet -p bubblebuffer-device-key --example generate_contract -- --check
```

The generator reads deterministic identity seeds and key-file inputs from the
fixture, recomputes their derived outputs and creates the proof vectors from
explicit label/role/origin/nonce inputs. It emits JSON to stdout; `--check`
compares the complete generated document byte for byte. Review regenerated
diffs. Never redirect directly onto the input fixture: compilation embeds it.

For an implementation in another language, consume the JSON directly:

- Binary strings use canonical, unpadded base64url unless their field name ends
  in `Hex`, in which case they use hexadecimal. `aadUtf8` is an exact UTF-8
  string; compare its bytes without Unicode normalization.
- For each `ids` entry, derive the Ed25519 public key from `seedHex`, hash its raw
  32 bytes with SHA-256 and compare `public` and `sha256Hex`. The identity's
  fingerprint is the first ten hash bytes, encoded with Crockford base32 as four
  groups of four symbols. Compare `id` and check supplied ID aliases normalize
  to the expected canonical spelling.
- For `keyFiles.plain`, validate seed, public key and ID consistency. For
  `keyFiles.passphrase`, derive Argon2id v1.3 using the stored salt, 65,536 KiB,
  three passes, one lane and 32 output bytes; compare `kdfKeyHex`. Canonicalize
  the header excluding `private` and `aead.nonce`, sorting property names by
  UTF-16 code units and minimally escaping strings. Compare `aadUtf8` and
  `aadHex`, then AES-256-GCM seal `seedHex` with that AAD and the stored nonce.
  Compare the entire ciphertext plus 16-byte tag with `file.private` and decrypt
  back to the seed. A JSON round trip alone does not prove byte compatibility.
- Require both `keyFiles.failures` entries to fail authentication. Reject an
  unsupported format before unlocking. Rewrapping retains identity, label and
  timestamp, supports optional passphrase protection, and generates fresh salt
  and nonce for protected output.
- For `relayProof.vectors`, prefix each of these fields with its byte length as
  an unsigned big-endian 32-bit integer: `label`, `role`, `origin`, raw 32-byte
  nonce, canonical `id`, raw 32-byte public key. Strings use UTF-8; role is exactly
  `host` or `viewer`. Compare the concatenated bytes with `encodingHex`, then
  SHA-256 them and compare `sha256Hex`. The Ed25519 signature authenticates those
  32 hash bytes. Validate ID/public-key consistency before accepting the proof.
- Accept the valid proof vectors, including `alternate-label`, which uses the
  independent label `independent-project-proof-v2`. Require `wrong-origin` to
  fail: it retains the host signature while changing the origin. Changing label,
  role, origin, nonce, ID or public key must also fail. Labels are required caller
  inputs; the API supplies no default. Origins are authenticated exactly as
  supplied, with no URL normalization.

The unit tests cover strict JSON and encodings, imported ID spelling, stable
serialization, deterministic sealing, protected failures, fresh protection,
RFC 8032 signing, libsodium-compatible key conversion, torsion rejection and
proof field binding. These fixtures exercise no storage or network operations.
