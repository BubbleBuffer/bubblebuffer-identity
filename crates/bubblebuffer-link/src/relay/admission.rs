use super::{
    Limits,
    wire::{self, Wire},
};
use crate::{Error, Result, device::DeviceId};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;

pub use bubblebuffer_device_key::{RelayProof, RelayRole};

/// Host-owned policy layered after mandatory Ed25519 possession verification.
/// A route handler may capture its authenticated account/session in this object.
/// Callbacks are synchronous and should finish promptly without logging secrets.
/// The proof binds role, origin and nonce. Requested targets are separate routing
/// input: `may_connect` authorizes them, then the host tunnel authorizes its peer.
pub trait RelayAdmission: Send + Sync {
    fn admit_host(&self, _host: &DeviceId, _proof: &RelayProof) -> bool {
        true
    }
    fn admit_client(&self, _client: &DeviceId, _proof: &RelayProof) -> bool {
        true
    }
    fn may_connect(&self, _client: &DeviceId, _host: &DeviceId, _proof: &RelayProof) -> bool {
        true
    }
}

/// Standalone policy: any device with a valid possession proof may register or
/// request a connection. The host's encrypted tunnel still authorizes its peer.
#[derive(Default)]
pub struct PermissiveAdmission;
impl RelayAdmission for PermissiveAdmission {}

pub(super) async fn authenticate<S>(
    ws: &mut WebSocketStream<S>,
    limits: &Limits,
    origin: &str,
) -> Result<(RelayProof, Option<DeviceId>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut challenge = [0; 32];
    OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|_| Error::Protocol("relay challenge entropy unavailable"))?;
    wire::send(ws, &Wire::Challenge(challenge), limits).await?;
    let Wire::Auth {
        role,
        key,
        signature,
        target,
    } = wire::recv(ws, limits).await?
    else {
        return Err(Error::AuthenticationFailed);
    };
    let (role, target) = match role {
        wire::REGISTER if target.is_empty() => (RelayRole::Host, None),
        wire::CONNECT => (
            RelayRole::Viewer,
            Some(DeviceId::parse(&target).map_err(|_| Error::AuthenticationFailed)?),
        ),
        _ => return Err(Error::AuthenticationFailed),
    };
    let proof = RelayProof::verify(
        wire::PROOF_LABEL,
        role,
        origin,
        challenge,
        DeviceId::from_public_key(&key),
        key,
        signature,
    )
    .map_err(|_| Error::AuthenticationFailed)?;
    Ok((proof, target))
}

pub(super) fn permitted(
    policy: &dyn RelayAdmission,
    proof: &RelayProof,
    target: Option<&DeviceId>,
) -> bool {
    let id = DeviceId::from_public_key(&proof.public_key);
    match proof.role {
        RelayRole::Host => policy.admit_host(&id, proof),
        RelayRole::Viewer => target.is_some_and(|target| {
            policy.admit_client(&id, proof) && policy.may_connect(&id, target, proof)
        }),
    }
}
