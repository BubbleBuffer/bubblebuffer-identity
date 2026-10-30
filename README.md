# bubblebuffer-identity

Reusable Rust device identities, encrypted peer transport, pairing and a WebSocket rendezvous relay. Application messages remain opaque; applications own request authorization, user interfaces, account login and deployment.

## Crates

| Crate | Responsibility |
| --- | --- |
| `bubblebuffer-device-key` | Ed25519 identities, device IDs, fingerprints, protected/plain `.bpkey` files and X25519 key conversion. |
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

A successful Noise handshake proves possession of a device key. Each peer also exchanges its Ed25519 identity over the encrypted channel and binds it to the authenticated X25519 static key. `PeerAuthorizer` then decides whether that device may connect and grants a `read`, `edit` or `full` profile. Both peers must accept before application data is available. The application must enforce that profile for each operation.

Pairing adds an explicitly approved peer to the local store. Trust can come from that pairing store, a validated `DeviceListAuthorizer`, or a custom `PeerAuthorizer` integrating account sign-in. Constrain an initiating client's policy to the intended host. Policy changes govern new handshakes; existing tunnels retain their grant, so immediate revocation requires closing them or enforcing current policy at request dispatch.

OAuth/OIDC belongs to the embedding application or account hub. A hub authenticates the account, validates its tokens and device ownership, and supplies device keys and profiles to `DeviceListAuthorizer`. The hub is therefore trusted for account membership and authorization. No OAuth/OIDC implementation, token storage or automatic account-to-device binding is supplied here.

Relay admission is a separate boundary. Device-key proof is mandatory; `RelayAdmission` can additionally enforce the authenticated account and device-owner map. A hub can mount `RelayRouter` on its authenticated WebSocket route and pass account context from the validated HTTP session. The standalone listener uses permissive admission for valid device proofs; end-to-end tunnel authorization still applies.

The relay sees device identities, connection metadata, timing and message sizes. It can interrupt traffic but cannot read authenticated tunnel plaintext. Protect unlocked keys and endpoint displays, compare pairing numbers before approval, and treat unprotected key files as secrets.
