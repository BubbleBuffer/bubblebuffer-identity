use crate::{DeviceId, DeviceKeyError};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    Host,
    Client,
}

/// Public evidence of Ed25519 key possession. Verification establishes possession only;
/// callers still decide which devices and connections their application permits.
/// This type deliberately does not implement Debug.
pub struct RelayProof {
    pub public_key: [u8; 32],
    pub challenge: [u8; 32],
    pub signature: [u8; 64],
    pub role: RelayRole,
    pub target: Option<DeviceId>,
}

/// Relay challenge transcript. Role 2 registers a host with an empty target; role 3 connects
/// a client to the target ID. The target spelling is signed verbatim, before ID normalization.
pub fn relay_signed_bytes(challenge: &[u8; 32], role: u8, target: &str) -> Vec<u8> {
    let mut bytes = b"bubblebuffer-relay-v1\0".to_vec();
    bytes.extend_from_slice(challenge);
    bytes.push(role);
    bytes.extend_from_slice(target.as_bytes());
    bytes
}

impl RelayProof {
    pub fn verify(
        challenge: [u8; 32],
        role: u8,
        public_key: [u8; 32],
        signature: [u8; 64],
        target: &str,
    ) -> Result<Self, DeviceKeyError> {
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeviceKeyError::InvalidSignature)?
            .verify_strict(
                &relay_signed_bytes(&challenge, role, target),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| DeviceKeyError::InvalidSignature)?;
        let (role, target) = match role {
            2 if target.is_empty() => (RelayRole::Host, None),
            3 => (RelayRole::Client, Some(DeviceId::parse(target)?)),
            _ => return Err(DeviceKeyError::UnknownRole),
        };
        Ok(Self {
            public_key,
            challenge,
            signature,
            role,
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKey;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn possession_is_bound_to_challenge_role_and_exact_target() {
        let key = DeviceKey::from_seed(&[7; 32]);
        let challenge = [5; 32];
        let target = DeviceKey::from_seed(&[8; 32]).id().to_string();
        let signature = key.sign(&relay_signed_bytes(&challenge, 3, &target));
        let proof = RelayProof::verify(challenge, 3, key.public_key(), signature, &target).unwrap();
        assert_eq!(proof.target, Some(DeviceId::parse(&target).unwrap()));
        assert!(RelayProof::verify([6; 32], 3, key.public_key(), signature, &target).is_err());
        assert!(
            RelayProof::verify(
                challenge,
                3,
                DeviceKey::from_seed(&[9; 32]).public_key(),
                signature,
                &target
            )
            .is_err()
        );
        assert!(RelayProof::verify(challenge, 2, key.public_key(), signature, &target).is_err());
        assert!(
            RelayProof::verify(
                challenge,
                3,
                key.public_key(),
                signature,
                &target.to_lowercase()
            )
            .is_err()
        );
        let host_signature = key.sign(&relay_signed_bytes(&challenge, 2, ""));
        assert!(RelayProof::verify(challenge, 2, key.public_key(), host_signature, "").is_ok());
        for (role, target) in [(2, target.as_str()), (3, "bad"), (9, "")] {
            let signature = key.sign(&relay_signed_bytes(&challenge, role, target));
            assert!(
                RelayProof::verify(challenge, role, key.public_key(), signature, target).is_err()
            );
        }
    }

    #[test]
    fn possession_contract_vectors_pin_transcript_and_signature_bytes() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/device-keys-contract.json"))
                .unwrap();
        let decode =
            |value: &serde_json::Value| URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap();
        let unhex = |value: &serde_json::Value| {
            let value = value.as_str().unwrap();
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let seed: [u8; 32] = unhex(&fixture["ids"][0]["seedHex"]).try_into().unwrap();
        let key = DeviceKey::from_seed(&seed);
        for vector in fixture["relayPossession"]["vectors"].as_array().unwrap() {
            let challenge: [u8; 32] = unhex(&vector["challengeHex"]).try_into().unwrap();
            let role = vector["role"].as_u64().unwrap() as u8;
            let target = vector["target"].as_str().unwrap();
            let transcript = relay_signed_bytes(&challenge, role, target);
            assert_eq!(transcript, unhex(&vector["signedBytesHex"]));
            let signature: [u8; 64] = decode(&vector["signature"]).try_into().unwrap();
            let public_key: [u8; 32] = decode(&vector["public"]).try_into().unwrap();
            assert_eq!(key.sign(&transcript), signature);
            assert!(RelayProof::verify(challenge, role, public_key, signature, target).is_ok());
        }
    }
}
