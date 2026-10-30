# Device identity contract fixtures

`device-keys-contract.json` contains public deterministic test data. Every seed,
passphrase, salt, nonce and derived secret is deliberately public and must never
be used for a real identity.

The original contract was extracted from the release source's remote device
module. All original sections and non-format inputs remain present. The current
key-file identifier is `bubblebuffer-device-key`; changing that authenticated
header requires regenerating its canonical AAD and AES-GCM ciphertext/tag.
Wrong-passphrase and tampered-label failure vectors retain their deliberate
corruption and use the newly sealed ciphertext.

The historical `handshake` and `relayProof` sections are opaque compatibility
records retained unchanged. They describe an earlier protocol, not the current
Noise transport or binary relay possession proof. `relayPossession` contains
current binary challenge transcripts and signatures.

The `keyFiles.legacy` vector uses the neutral identifier `legacy-device-key-v1`.
The key-file reader accepts legacy identifiers only when its caller supplies
them through `parse_with_legacy_formats`. Unlock authenticates the exact stored
identifier. `to_json` refuses legacy files with `LegacyRewrapRequired`; `rewrap`
unlocks and recreates protection under the current identifier before writing.

On an authorized build host, regenerate with:

```sh
cargo run --quiet -p bubblebuffer-device-key --example generate_contract > /tmp/device-keys-contract.json
cp /tmp/device-keys-contract.json fixtures/device-keys-contract.json
cargo run --quiet -p bubblebuffer-device-key --example generate_contract -- --check
```

The generator reads deterministic inputs from the checked-in fixture, recomputes
key-file KDF/AAD/ciphertext and current possession proof outputs, and emits JSON
to stdout. It preserves historical sections and unrelated field values. `--check`
compares the entire generated document byte for byte. Review any regenerated
diff. Never redirect directly onto the input fixture: compilation embeds it.

Unit tests separately validate strict JSON, canonical encodings, identity
consistency, deterministic sealing, authenticated metadata, protected failures,
fresh random protection, legacy migration and possession proof field binding.

For an implementation in another language, consume the JSON directly:

- Decode binary strings as canonical, unpadded base64url unless the field name
  ends in `Hex`; decode those as hexadecimal. `aadUtf8` and `plaintextUtf8` are
  exact UTF-8 strings. Preserve their Unicode values, quoting and control escapes
  when deriving bytes; canonical JSON uses UTF-16 property-name ordering.
- For each `ids` entry, derive the Ed25519 public key from `seedHex`, hash its raw
  32 bytes with SHA-256 and compare `public`, `sha256Hex` and the 80-bit Crockford
  ID. Also check the supplied alias spelling normalizes to the expected ID.
- For `keyFiles.plain`, validate seed, public key and ID consistency. For
  `keyFiles.passphrase`, derive Argon2id v1.3 with the stored salt, 65,536 KiB,
  three passes, one lane and 32 output bytes; compare `kdfKeyHex`. Canonicalize
  the header excluding `private` and `aead.nonce`, compare both AAD fields, then
  AES-256-GCM seal `seedHex` with that AAD and the stored nonce. Compare the
  complete ciphertext plus 16-byte tag against `file.private`, and decrypt back
  to the seed. A JSON round trip alone does not establish byte compatibility.
- Require both `keyFiles.failures` entries to fail authentication. Accept
  `keyFiles.legacy` only after explicitly enabling its neutral format, and verify
  its AAD and successful decryption using that stored format. Changing only the
  format to the current value must fail authentication; migration must unlock
  and reseal with fresh salt and nonce under the current format.
- For `relayPossession.vectors`, construct domain bytes
  `bubblebuffer-relay-v1` followed by a zero byte, the 32-byte challenge, the
  one-byte role and exact UTF-8 target spelling. Compare `signedBytesHex`, its
  SHA-256 and the Ed25519 signature. Verify the signature, then require role 2
  to have an empty target or role 3 to have a valid target ID. Altering challenge,
  role, target or public key must invalidate the proof.

The retained historical sections are reference data for implementations of
those earlier protocols; their presence does not imply support by the current
Rust crates. All positive, negative and legacy inputs remain public test data.
