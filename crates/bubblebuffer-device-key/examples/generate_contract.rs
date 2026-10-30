//! Regenerate deterministic key-file and current possession-proof outputs from fixture inputs.
//! All keys, passphrases, salts and nonces in this example are public test material.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bubblebuffer_device_key::{DeviceId, DeviceKey, relay_signed_bytes};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INPUT: &str = include_str!("../../../fixtures/device-keys-contract.json");
const FORMAT: &str = "bubblebuffer-device-key";
const LEGACY: &str = "legacy-device-key-v1";

fn text(value: &Value) -> &str {
    value.as_str().expect("fixture string")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}
fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text(value)).unwrap()
}

// Fixture metadata uses ASCII property names, so byte ordering is also RFC 8785 UTF-16 ordering.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(entries) => {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(key, value)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).unwrap(),
                            canonical(value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        _ => serde_json::to_string(value).unwrap(),
    }
}

fn seal(vector: &mut Value, format: &str) {
    vector["file"]["format"] = json!(format);
    let mut header = vector["file"].clone();
    header.as_object_mut().unwrap().remove("private");
    header["aead"].as_object_mut().unwrap().remove("nonce");
    let aad = canonical(&header);
    let salt = decode(&vector["file"]["kdf"]["salt"]);
    let nonce = decode(&vector["file"]["aead"]["nonce"]);
    let seed = unhex(text(&vector["seedHex"]));
    let mut kdf_key = [0; 32];
    let params = Params::new(65_536, 3, 1, Some(32)).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(text(&vector["passphrase"]).as_bytes(), &salt, &mut kdf_key)
        .unwrap();
    let cipher = Aes256Gcm::new_from_slice(&kdf_key).unwrap();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &seed,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    vector["kdfKeyHex"] = json!(hex(&kdf_key));
    vector["aadUtf8"] = json!(aad);
    vector["aadHex"] = json!(hex(text(&vector["aadUtf8"]).as_bytes()));
    vector["file"]["private"] = json!(URL_SAFE_NO_PAD.encode(sealed));
}

fn generate() -> String {
    let mut fixture: Value = serde_json::from_str(INPUT).unwrap();
    // Preserve all historical sections and all input fields. Only the format-dependent key
    // file outputs change; historical protocol vectors are opaque compatibility records.
    fixture["keyFiles"]["plain"]["file"]["format"] = json!(FORMAT);
    seal(&mut fixture["keyFiles"]["passphrase"], FORMAT);
    let private = fixture["keyFiles"]["passphrase"]["file"]["private"].clone();
    for failure in fixture["keyFiles"]["failures"].as_array_mut().unwrap() {
        failure["file"]["format"] = json!(FORMAT);
        // Keep deliberate wrong-passphrase and tampered-label inputs. Both retain the valid
        // original file's ciphertext, so they remain authentication failures after migration.
        failure["file"]["private"] = private.clone();
    }
    let mut legacy = fixture["keyFiles"]["passphrase"].clone();
    seal(&mut legacy, LEGACY);
    fixture["keyFiles"]["legacy"] = legacy;

    let mut proofs = Vec::new();
    for (role, name, target) in [
        (2, "host", String::new()),
        (3, "client", text(&fixture["ids"][1]["id"]).to_owned()),
    ] {
        let seed: [u8; 32] = unhex(text(&fixture["ids"][0]["seedHex"]))
            .try_into()
            .unwrap();
        let key = DeviceKey::from_seed(&seed);
        let challenge = [0x42; 32];
        let signed = relay_signed_bytes(&challenge, role, &target);
        proofs.push(json!({
            "name": name, "role": role, "target": target,
            "challengeHex": hex(&challenge), "public": URL_SAFE_NO_PAD.encode(key.public_key()),
            "signedBytesHex": hex(&signed), "sha256Hex": hex(&Sha256::digest(&signed)),
            "signature": URL_SAFE_NO_PAD.encode(key.sign(&signed)), "expected": "valid"
        }));
        assert_eq!(key.id(), DeviceId::from_public_key(&key.public_key()));
    }
    fixture["relayPossession"] = json!({"vectors": proofs});
    serde_json::to_string_pretty(&fixture).unwrap() + "\n"
}

fn main() {
    let generated = generate();
    if std::env::args().any(|argument| argument == "--check") {
        assert_eq!(
            generated, INPUT,
            "fixture differs; regenerate and review the diff"
        );
    } else {
        print!("{generated}");
    }
}
