# bubblebuffer-identity

Reusable Rust device identities, encrypted peer transport, pairing and a WebSocket rendezvous relay. Application messages remain opaque; applications own request authorization, user interfaces, account login and deployment.

## Crates

| Crate | Responsibility |
| --- | --- |
| `bubblebuffer-device-key` | Ed25519 identities, Crockford device fingerprints/IDs, protected/plain `.bpkey` files, generic relay proofs and X25519 key conversion. |
| `bubblebuffer-link` | Noise tunnels, bounded byte/WebSocket carriers, pairing, persistent device stores, caller-owned trust and relay client/server APIs. |

`bubblebuffer-relay` is the standalone rendezvous binary supplied by
`bubblebuffer-link`.

Applications intended to share these primitives:

- BubblePaw
- Scratch

See [transport and protocol documentation](docs/remote.md) for key-file details, framing, pairing, relay integration and operational limits.

## Depending on a tagged revision

```toml
[dependencies]
bubblebuffer-device-key = { git = "https://github.com/BubbleBuffer/bubblebuffer-identity", tag = "v0.1.0" }
bubblebuffer-link = { git = "https://github.com/BubbleBuffer/bubblebuffer-identity", tag = "v0.1.0" }
```

`v0.1.0` is an illustrative tag, not a claim that a release exists. Replace it with a published tag you have reviewed. A single repository tag pins both crates to the same revision.

## Trust and authorization

Pairing adds an approved peer to a store; that store or an embedder-owned `PeerAuthorizer` admits the device identity bound to the Noise tunnel and grants a profile that the application enforces, while account sign-in and OIDC validation belong to the embedder. Relay proofs bind the required protocol label, explicit relay origin, fresh nonce and device identity, while `RelayAdmission` controls routing and the host's `PeerAuthorizer` controls access rather than relying on a separate target-binding signature. The relay sees routing metadata and ciphertext; constrain client trust to the intended host, and close active sessions when immediate revocation is required.

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
