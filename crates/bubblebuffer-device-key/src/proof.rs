use crate::{DeviceId, DeviceKeyError};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    Host,
    Viewer,
}

impl RelayRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(role: &str) -> Result<Self, DeviceKeyError> {
        match role {
            "host" => Ok(Self::Host),
            "viewer" => Ok(Self::Viewer),
            _ => Err(DeviceKeyError::UnknownRole),
        }
    }
}

/// Verified Ed25519 key possession. Callers supply their own protocol label and expected
/// origin, then apply their admission policy. This type deliberately does not implement Debug.
pub struct RelayProof {
    pub label: String,
    pub role: RelayRole,
    pub origin: String,
    pub nonce: [u8; 32],
    pub id: DeviceId,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Each field is prefixed by its byte length as a big-endian u32, in this exact order:
/// label, role, origin, nonce, canonical device ID, public key. Strings are UTF-8; the nonce
/// and public key are raw bytes. The caller must always choose the protocol label.
pub fn relay_proof_bytes(
    label: &str,
    role: RelayRole,
    origin: &str,
    nonce: &[u8; 32],
    id: DeviceId,
    public_key: &[u8; 32],
) -> Result<Vec<u8>, DeviceKeyError> {
    let id = id.to_string();
    let mut bytes = Vec::new();
    for field in [
        label.as_bytes(),
        role.as_str().as_bytes(),
        origin.as_bytes(),
        nonce,
        id.as_bytes(),
        public_key,
    ] {
        let length =
            u32::try_from(field.len()).map_err(|_| DeviceKeyError::InvalidLength("proof field"))?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

/// SHA-256 of the length-prefixed transcript. Sign this 32-byte hash with Ed25519.
pub fn relay_proof_hash(
    label: &str,
    role: RelayRole,
    origin: &str,
    nonce: &[u8; 32],
    id: DeviceId,
    public_key: &[u8; 32],
) -> Result<[u8; 32], DeviceKeyError> {
    Ok(Sha256::digest(relay_proof_bytes(
        label, role, origin, nonce, id, public_key,
    )?)
    .into())
}

impl RelayProof {
    pub fn verify(
        label: &str,
        role: RelayRole,
        origin: &str,
        nonce: [u8; 32],
        id: DeviceId,
        public_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, DeviceKeyError> {
        if id != DeviceId::from_public_key(&public_key) {
            return Err(DeviceKeyError::IdMismatch);
        }
        let hash = relay_proof_hash(label, role, origin, &nonce, id, &public_key)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeviceKeyError::InvalidSignature)?
            .verify_strict(&hash, &Signature::from_bytes(&signature))
            .map_err(|_| DeviceKeyError::InvalidSignature)?;
        Ok(Self {
            label: label.to_owned(),
            role,
            origin: origin.to_owned(),
            nonce,
            id,
            public_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKey;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn proof_binds_label_role_origin_nonce_id_and_public_key() {
        let key = DeviceKey::from_seed(&[7; 32]);
        let nonce = [5; 32];
        let label = "independent-proof-v2";
        let origin = "https://relay.example.test";
        let hash = relay_proof_hash(
            label,
            RelayRole::Host,
            origin,
            &nonce,
            key.id(),
            &key.public_key(),
        )
        .unwrap();
        let signature = key.sign(&hash);
        let verify = |label, role, origin, nonce, id, public| {
            RelayProof::verify(label, role, origin, nonce, id, public, signature)
        };
        assert!(
            verify(
                label,
                RelayRole::Host,
                origin,
                nonce,
                key.id(),
                key.public_key()
            )
            .is_ok()
        );
        assert!(
            verify(
                "other-label",
                RelayRole::Host,
                origin,
                nonce,
                key.id(),
                key.public_key()
            )
            .is_err()
        );
        assert!(
            verify(
                label,
                RelayRole::Viewer,
                origin,
                nonce,
                key.id(),
                key.public_key()
            )
            .is_err()
        );
        assert!(
            verify(
                label,
                RelayRole::Host,
                "https://other.example.test",
                nonce,
                key.id(),
                key.public_key()
            )
            .is_err()
        );
        assert!(
            verify(
                label,
                RelayRole::Host,
                origin,
                [6; 32],
                key.id(),
                key.public_key()
            )
            .is_err()
        );
        let other = DeviceKey::from_seed(&[8; 32]);
        assert!(
            verify(
                label,
                RelayRole::Host,
                origin,
                nonce,
                other.id(),
                key.public_key()
            )
            .is_err()
        );
        assert!(
            verify(
                label,
                RelayRole::Host,
                origin,
                nonce,
                other.id(),
                other.public_key()
            )
            .is_err()
        );
        let alias = DeviceId::parse(&key.id().to_string().to_lowercase().replace('-', "")).unwrap();
        assert_eq!(
            relay_proof_hash(
                label,
                RelayRole::Host,
                origin,
                &nonce,
                alias,
                &key.public_key()
            )
            .unwrap(),
            hash
        );
        assert!(RelayRole::parse("client").is_err());
        assert!(RelayRole::parse("HOST").is_err());
    }

    #[test]
    fn proof_contract_vectors_pin_encoding_hash_and_signature() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/device-keys-contract.json"))
                .unwrap();
        let unhex = |value: &serde_json::Value| {
            let value = value.as_str().unwrap();
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let decode =
            |value: &serde_json::Value| URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap();
        for vector in fixture["relayProof"]["vectors"].as_array().unwrap() {
            let label = vector["label"].as_str().unwrap();
            let role = RelayRole::parse(vector["role"].as_str().unwrap()).unwrap();
            let origin = vector["origin"].as_str().unwrap();
            let nonce = unhex(&vector["nonceHex"]).try_into().unwrap();
            let id = DeviceId::parse(vector["id"].as_str().unwrap()).unwrap();
            let public = decode(&vector["public"]).try_into().unwrap();
            let signature = decode(&vector["signature"]).try_into().unwrap();
            assert_eq!(
                relay_proof_bytes(label, role, origin, &nonce, id, &public).unwrap(),
                unhex(&vector["encodingHex"])
            );
            assert_eq!(
                relay_proof_hash(label, role, origin, &nonce, id, &public)
                    .unwrap()
                    .as_slice(),
                unhex(&vector["sha256Hex"])
            );
            assert_eq!(
                RelayProof::verify(label, role, origin, nonce, id, public, signature).is_ok(),
                vector["expected"] == "valid"
            );
        }
    }
}
