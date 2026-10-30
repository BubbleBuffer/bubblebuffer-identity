//! Regenerate deterministic key-file and current possession-proof outputs from fixture inputs.
//! All keys, passphrases, salts and nonces in this example are public test material.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bubblebuffer_device_key::{
    DeviceId, DeviceKey, RelayRole, relay_proof_bytes, relay_proof_hash,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INPUT: &str = include_str!("../../../fixtures/device-keys-contract.json");
const FORMAT: &str = "bubblebuffer-device-key";

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
    let input: Value = serde_json::from_str(INPUT).unwrap();
    let mut fixture = json!({
        "ids": input["ids"],
        "keyFiles": {
            "plain": input["keyFiles"]["plain"],
            "passphrase": input["keyFiles"]["passphrase"],
            "failures": input["keyFiles"]["failures"]
        }
    });
    for vector in fixture["ids"].as_array_mut().unwrap() {
        let seed: [u8; 32] = unhex(text(&vector["seedHex"])).try_into().unwrap();
        let key = DeviceKey::from_seed(&seed);
        vector["public"] = json!(URL_SAFE_NO_PAD.encode(key.public_key()));
        vector["sha256Hex"] = json!(hex(&Sha256::digest(key.public_key())));
        vector["id"] = json!(key.id().to_string());
        if vector.get("parse").is_some() {
            let parsed = DeviceId::parse(text(&vector["parse"]["input"])).unwrap();
            vector["parse"]["canonical"] = json!(parsed.to_string());
        }
    }
    for name in ["plain", "passphrase"] {
        let vector = &mut fixture["keyFiles"][name];
        let seed: [u8; 32] = unhex(text(&vector["seedHex"])).try_into().unwrap();
        let key = DeviceKey::from_seed(&seed);
        vector["file"]["public"] = json!(URL_SAFE_NO_PAD.encode(key.public_key()));
        vector["file"]["id"] = json!(key.id().to_string());
        if name == "plain" {
            vector["file"]["private"] = json!(URL_SAFE_NO_PAD.encode(seed));
        }
    }
    fixture["keyFiles"]["plain"]["file"]["format"] = json!(FORMAT);
    seal(&mut fixture["keyFiles"]["passphrase"], FORMAT);
    let private = fixture["keyFiles"]["passphrase"]["file"]["private"].clone();
    for failure in fixture["keyFiles"]["failures"].as_array_mut().unwrap() {
        failure["file"]["format"] = json!(FORMAT);
        // Keep deliberate wrong-passphrase and tampered-label inputs. Both retain the valid
        // original file's ciphertext, so they remain authentication failures after migration.
        failure["file"]["private"] = private.clone();
    }
    let mut proofs = Vec::new();
    for (label, role, name, identity, nonce_start) in [
        ("bubblebuffer-relay-v1", RelayRole::Host, "host", 1, 0xa0_u8),
        (
            "bubblebuffer-relay-v1",
            RelayRole::Viewer,
            "viewer",
            0,
            0xc0_u8,
        ),
        (
            "independent-project-proof-v2",
            RelayRole::Host,
            "alternate-label",
            1,
            0xa0_u8,
        ),
    ] {
        let seed: [u8; 32] = unhex(text(&fixture["ids"][identity]["seedHex"]))
            .try_into()
            .unwrap();
        let key = DeviceKey::from_seed(&seed);
        let nonce = std::array::from_fn(|index| nonce_start + index as u8);
        let origin = "https://example.test";
        let encoded =
            relay_proof_bytes(label, role, origin, &nonce, key.id(), &key.public_key()).unwrap();
        let hash =
            relay_proof_hash(label, role, origin, &nonce, key.id(), &key.public_key()).unwrap();
        proofs.push(json!({
            "name": name, "label": label, "role": role.as_str(), "origin": origin,
            "nonceHex": hex(&nonce), "nonce": URL_SAFE_NO_PAD.encode(nonce),
            "id": key.id().to_string(), "public": URL_SAFE_NO_PAD.encode(key.public_key()),
            "encodingHex": hex(&encoded), "sha256Hex": hex(&hash),
            "signature": URL_SAFE_NO_PAD.encode(key.sign(&hash)), "expected": "valid"
        }));
    }
    // An invalid vector retains the valid host's signature but changes the origin.
    let mut wrong_origin = proofs[0].clone();
    wrong_origin["name"] = json!("wrong-origin");
    wrong_origin["origin"] = json!("https://other-relay.example.test");
    wrong_origin["expected"] = json!("invalid");
    let nonce = decode(&wrong_origin["nonce"]).try_into().unwrap();
    let public = decode(&wrong_origin["public"]).try_into().unwrap();
    let id = DeviceId::parse(text(&wrong_origin["id"])).unwrap();
    wrong_origin["encodingHex"] = json!(hex(&relay_proof_bytes(
        text(&wrong_origin["label"]),
        RelayRole::Host,
        text(&wrong_origin["origin"]),
        &nonce,
        id,
        &public
    )
    .unwrap()));
    wrong_origin["sha256Hex"] = json!(hex(&relay_proof_hash(
        text(&wrong_origin["label"]),
        RelayRole::Host,
        text(&wrong_origin["origin"]),
        &nonce,
        id,
        &public
    )
    .unwrap()));
    proofs.push(wrong_origin);
    fixture["relayProof"] = json!({"vectors": proofs});
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
