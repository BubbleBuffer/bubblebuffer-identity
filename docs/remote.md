# Remote transport

`bubblebuffer-link` carries opaque host-protocol messages between paired devices.
Together with `bubblebuffer-device-key`, it supplies identities, key files,
bounded encrypted streams, pairing stores and an authenticated WebSocket
rendezvous relay. It does not interpret host requests
or enforce permission profiles; the host dispatcher must authorize each request.

## Device identities and `.bpkey`

An identity is an Ed25519 seed and its public key. The device ID is the first ten
bytes of SHA-256 over the raw public key, encoded as sixteen Crockford base32
characters in four groups, such as `K7MQ-2X9F-D4RT-8WHN`. Parsing accepts ASCII
letter case, hyphens and Crockford aliases O/0 and I/L/1; spaces are rejected.
This 80-bit device ID is the fingerprint; there is no separate full SHA-256
fingerprint API.

Key-file paths and passphrase acquisition belong to the application. The format
supports both protected and plain files; callers choose protection explicitly
using `Some(passphrase)`. Public compatibility vectors live in
[`fixtures`](../fixtures/README.md).
The contract fixture contains only `ids`, `keyFiles` and `relayProof` sections.

Version 1 is JSON with `format: "bubblebuffer-device-key"`, `version: 1`,
`type: "ed25519"`, `id`, `label`, `created`, `public`, `kdf`, `aead` and `private`.
Public key, salt, nonce and private bytes use canonical unpadded base64url.
The reader and writer support only `bubblebuffer-device-key`; unknown format
identifiers return an error. Authenticated metadata uses the stored, validated
`format` field when constructing AAD.

- Protected: Argon2id v1.3, 65,536 KiB, three passes, one lane, 16-byte salt,
  32-byte output; AES-256-GCM with a 12-byte nonce. `private` contains the encrypted
  32-byte seed followed by its 16-byte authentication tag.
- Authenticated metadata is canonical JSON of the header, excluding `private`
  and `aead.nonce`, retaining `aead.alg` and the KDF salt. Imported ID spelling is
  preserved because it is authenticated. Unknown/duplicate fields and malformed
  encodings are rejected. Public-key/seed/ID consistency is checked.
- Plain: `kdf` and `aead` are both null; `private` contains the seed. Treat this
  JSON as a secret. Debug implementations omit private material.

X25519 static keys use the [libsodium conversion](https://doc.libsodium.org/advanced/ed25519-curve25519):
SHA-512 of the Ed25519 seed, then clamp the first 32 bytes; convert the public
Edwards point to Montgomery form. Invalid/noncanonical, small-order and
non-prime-subgroup public keys are rejected. Secrets and Argon2 work buffers are
zeroized on drop. Applications own key-file paths and passphrase acquisition.

## Tunnel and framing

Ordinary sessions use `Noise_XX_25519_ChaChaPoly_BLAKE2s`, with the prologue
`bubblebuffer-link/noise/v1`. After the handshake both peers check the received
static X25519 key against an encrypted Ed25519 identity exchange. The conversion
must match before the tunnel calls the caller's `PeerAuthorizer` with the derived
device ID and Ed25519 public key. Peers then exchange encrypted admission
decisions. Application data is unavailable until both accept. The returned
tunnel exposes the peer identity and locally granted profile in `authorization()`.

## Trust

Trust and transport are separate boundaries. `PeerAuthorizer` decides which peer
is authorized and returns its `read`, `edit` or `full` profile. Its public-key
argument is the Ed25519 identity already bound to the Noise static key, not an
unverified ID supplied by the relay. Authorization runs on each new handshake.

A standalone host can use `PairStore<PairedClient>` as the host authorizer. The
pairing flow explicitly approves and saves clients; their saved profiles govern
the resulting grants. `PairStore<PairedHost>` admits saved hosts with a full grant.
When connecting to a particular host, constrain the client's authorizer to that
host. Public-key arrays/slices remain a convenience authorizer with full grants.

An embedder can instead supply a `DeviceListAuthorizer` populated with validated
`(device ID, Ed25519 public key, profile)` records. `replace()` validates the whole
new list before atomically swapping it; clones share the same live list. A failed
replacement preserves the old snapshot. A removed device is rejected on its next
handshake. Existing tunnels retain their original grant; the embedder must close
them for immediate revocation. Per-device pairing is not required for list-based
trust.

An account hub can authenticate users with OAuth/OIDC, refresh the list from the
account's devices, and supply the meeting point. The hub is trusted to attest
account membership and per-device profiles. Authentication and token validation
belong to the embedder; this library does not implement an OIDC client or identity
provider. Device identities and encrypted tunnels remain independent of account
login. The relay sees ciphertext and routing metadata. Host dispatchers enforce
the returned profiles for individual operations.

## Carriers

`FrameIo` makes the tunnel independent of its carrier:

- `ByteFrames<T>` accepts any Tokio `AsyncRead + AsyncWrite + Unpin + Send`.
  Each record has a four-byte big-endian length and that many bytes. The length
  is checked before allocating.
- `WebSocketFrames<T>` sends one record per binary message. Construct sockets
  using `frame::websocket_config()` so individual frames and fragmented message
  reassembly are bounded before allocation. Unbounded socket configurations and
  text messages are rejected; Ping/Pong controls are handled by the carrier.
- `RelaySession` implements the same interface and strips the relay envelope.

The [Noise wire maximum](https://noiseprotocol.org/noise.html#message-format) is
65,535 bytes including the 16-byte AEAD tag, below the specified 64 KiB plaintext
cap. An encrypted continuation byte leaves 65,518 payload bytes per chunk.
Continuation 1 means another full chunk follows; 0 ends a message. The aggregate
message limit is 16 MiB, including for untrusted senders. Empty messages work.
Malformed, altered, replayed and out-of-order records fail authentication or
framing. A failed or cancelled tunnel operation invalidates that tunnel; reconnect
instead of guessing whether a nonce or external effect was consumed. Delivery
does not establish host-operation completion and must not trigger effect replay.

## Pairing and stores

The host creates `PairingCode::generate()`: ten independently random Crockford
characters (50 bits), valid for five minutes on a monotonic clock. The host owns
the code and serializes attempts through a mutable borrow. Wrong-code attempts
do not consume it; a successful PSK proof consumes it before user confirmation,
including a declined or interrupted approval.
Code entry ignores hyphens and ASCII spaces and accepts ASCII letter case and
Crockford aliases. This differs from device ID parsing, which rejects spaces.

Pairing uses `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. The PSK is Argon2id v1.3
with 65,536 KiB, three passes, one lane and a 32-byte result. Its password is the
normalized ten-character code and its salt is the UTF-8 canonical, grouped host
device ID. Expensive derivation runs on Tokio's blocking pool. Before Noise,
the host sends a ready/version/host-ID record or an expired/reused status. After
message three, it sends a status so the initiator can distinguish a wrong PSK.
These cleartext statuses can be spoofed to deny service; they do not grant trust.

Both sides then exchange encrypted Ed25519 identities and bind them to the
handshake's static keys. The client verifies that the public key matches the
expected host ID. The comparison is the first four big-endian bytes of
SHA-256(`"bubblebuffer-pair-comparison-v1" || handshake_hash`), modulo 1,000,000,
formatted as six digits. `PendingHost::comparison()` and
`PendingClient::comparison()` expose the same number.

The caller displays both numbers. Only after the host user confirms should it
call `PendingHost::approve(name, profile, store)`; `decline()` sends an encrypted
rejection. Approval checks the deadline again, saves the client and sends an
encrypted decision. `PendingClient::finish(store)` saves the host only after
that decision. Wrong-code, preflight-expired, reused and declined outcomes have
distinct errors. Expiry during an interrupted identity exchange can appear as
a transport error to the other side; no approval or client store entry is created.
A crash/disconnect between the two local commits can leave one side paired;
inspect/revoke that entry and issue a fresh code. No automatic approval retry.

`PairStore<PairedClient>` holds the client public key, host-chosen name and
`read`, `edit` or `full` profile. `PairStore<PairedHost>` holds the host ID, public
key, name and caller-supplied reach address. Each caller supplies its JSON path.
The versioned document has `version: 1` and a `devices` object keyed by canonical
ID. Keys, names and IDs are validated on load. Missing means empty; corrupt
means error. Files are capped at 4 MiB. Writes use a random same-directory
temporary file, flush/sync and rename; Unix files are mode 0600 and the parent
directory is synced. A post-rename directory-sync failure returns
`StoreDurability`: the new snapshot is already committed and remains reflected
in memory, while crash durability is uncertain. Serialize writers per path.
`revoke(id)` deletes an entry
and atomically saves. Revocation affects future admissions; the host must also
close any already active sessions it wants to revoke immediately.

## Relay

The caller supplies an explicit relay origin, and possession proofs bind that
origin and a fresh nonce to the device identity to prevent replay across origins
or challenges. `RelayAdmission` authorizes routing targets; the host's
`PeerAuthorizer` and end-to-end Noise authentication decide host access, without
a separate target-binding signature. The relay forwards ciphertext and can
observe metadata or interrupt traffic, while the application enforces each
tunnel's granted profile.

Run `bubblebuffer-relay ORIGIN [IP:PORT]` (default listen address
`127.0.0.1:8787`), for example:

```sh
bubblebuffer-relay https://relay.example.test 127.0.0.1:8787
```

This plain WebSocket
listener is intended behind Caddy's TLS endpoint. Host/client APIs support
`wss://` with native root certificates. TLS termination does not decrypt Noise.
Configuration and limits are exposed by `RelayConfig` and `Limits`. A `Relay`
owns its connection tasks; `shutdown().await` closes and joins them. Ctrl-C
shuts down the binary. The library owns no operating-system background process.
Construct server configuration with `RelayConfig::new(origin)`; mounted routes
use `RelayRouter::new(RelayConfig::new(origin))`. Every client API requires the
same nonempty origin string explicitly, including caller-created sockets; it is
compared as exact UTF-8 bytes, without URL derivation or normalization.

Every connection receives a fresh random 32-byte challenge. The generic
device-key proof requires an explicit protocol label. Its transcript is the
ordered sequence of label, role, origin, nonce, canonical device ID and public
key, each prefixed by its byte length as an unsigned 32-bit big-endian integer.
Strings use UTF-8 (`host` or `viewer` for the role); nonce and public key use raw
bytes. `relay_proof_bytes` constructs the transcript and `relay_proof_hash`
returns its SHA-256 digest.
The device signs SHA-256 of this transcript with Ed25519. The link relay supplies
`bubblebuffer-relay-v1` as its label. Verification binds all fields and rejects a
proof replayed against a fresh challenge. A registration ID is derived from its
authenticated public key.
Relay protocol compatibility and key-file compatibility are separate contracts.

`RelayAdmission` is the policy hook after mandatory device-key proof verification.
It receives a verified `RelayProof` and decides `admit_host`, `admit_client` and
`may_connect(client, host)`. The default `PermissiveAdmission`, used by the binary,
admits any valid device proof and permits any target; the target tunnel's
`PeerAuthorizer` still decides whether application traffic is allowed.
`RelayConfig.admission` supplies a policy for the standalone listener.

For a hub-owned HTTP route, share a `RelayRouter` between accepted sockets. Use
`router.websocket_config()` before upgrading, authenticate the HTTP account/session
in the hub, and call `router.serve_websocket(socket, peer_ip, admission).await`.
The admission object can capture the authenticated account and its device-owner
map, admitting only owned devices and connections within that account. Untrusted
relay messages cannot set this context. No OAuth implementation or credentials
are stored in this crate. `register_socket` and `connect_socket` also accept
caller-created client WebSockets, allowing the embedder to supply authentication
headers/cookies at upgrade without putting credentials in URLs.
Their signatures are `register_socket(socket, origin, key, limits)` and
`connect_socket(socket, origin, key, target, limits)`.

The router applies common routing and connection limits to all these sockets and
rejects sockets whose frame/message configuration lacks the required bounds.
`Limits::websocket_config()` supplies the corresponding client configuration.
The hub owns the serving futures/tasks; cancelling one releases its registration,
sessions and IP slot. `router.shutdown().await` stops admission and drains active
serving calls. Pass a trusted peer IP from the transport or trusted proxy layer,
not arbitrary forwarded headers.
Admission hooks run when registering or connecting; immediate account/session
revocation also requires the hub to cancel the affected active serving tasks.

One binary WebSocket message is one relay frame. Integers are unsigned big-endian.

| Tag | Meaning | Body after tag |
| --- | --- | --- |
| 1 | Challenge | 32-byte nonce |
| 2 | Register | 32-byte public key, 64-byte signature; empty target |
| 3 | Connect | 32-byte public key, 64-byte signature, target ID UTF-8 |
| 4 | Registered | empty |
| 5 | Incoming | 8-byte session ID, 32-byte client public key |
| 6 | Accept | 8-byte session ID |
| 7 | Data | 8-byte session ID, opaque Noise record |
| 8 | Close | 8-byte session ID |
| 9 | Connected | 8-byte session ID, 32-byte host public key |
| 10 | Reject | empty |

`register(url, origin, key, limits)` returns a `Host`. Its `accept()` returns
independent `RelaySession`s over the same registration.
`connect(url, origin, key, target, limits)`
waits for the host to accept. Each session runs its own Noise handshake and
nonce sequence. The relay's authenticated identity is a routing hint: the host
and client still verify their paired static keys end to end. Session IDs cannot
address another client's stream. Duplicate host registrations are rejected.

For example, the host registers and waits for a session:

```rust,ignore
let origin = "https://relay.example.test";
let url = "wss://relay.example.test/transport";
let mut host = register(url, origin, &host_key, Limits::default()).await?;
let session = host.accept().await?;
```

The client connects with the same origin and the intended host ID:

```rust,ignore
let origin = "https://relay.example.test";
let url = "wss://relay.example.test/transport";
let session = connect(url, origin, &client_key, &host_key.id(), Limits::default()).await?;
```

The URL selects the endpoint; the origin is the separately configured proof
audience and must match the server even behind a reverse proxy.

Defaults: 65,535 data bytes, 120-second idle timeout, 32 connections per source
IP, 16 pending clients and 128 total sessions per host, and bounded queues of 16.
WebSocket frame/message allocation also has an envelope allowance. Queues fail
closed under overload. Behind Caddy the source IP is the proxy's IP, so this
limit becomes shared unless separate trusted proxy handling is added later.
State is transient: online registrations and the live routing/limit bookkeeping
needed to forward sessions; nothing is persisted. Logs never include payloads.

## Threat notes and verification

The relay sees metadata only: device IDs/public keys, who talks to whom and when,
connection IPs, message sizes and timing. It can deny service, disconnect or delay
sessions. It cannot read or alter authenticated application plaintext. Reusing a
device identity across products intentionally makes that identity linkable.

The six-digit comparison guards pairing against a MITM relay; compare it on the
two physical devices before approving. This requires an honest display and user
confirmation. The code is a secret and must not be logged. Pairing and key-file
passphrases have separate roles. A stolen unlocked key or compromised endpoint
can impersonate that device; revoke it and replace its identity. Permission
profiles are metadata until the application dispatcher enforces them.

The workspace tests cover key-format vectors, key conversion, encrypted
byte/WebSocket streams, trust rejection, pairing outcomes, stores and multiplexed
relay sessions/limits. Coverage includes list replacement/revocation, synthetic
account-isolated mounted routes, blocked-socket shutdown, post-rename sync failure
and stalled pairing. These tests do not establish live OAuth/OIDC integration or
production deployment. Run the workspace checks in the repository CI configuration
for current results.
