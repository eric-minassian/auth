//! WebAuthn options returned to clients (protocol §8.1, §8.2).

use crate::config::Config;
use auth_core::b64;
use auth_core::decide::CEREMONY_TTL;
use serde_json::{Value, json};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Four Crockford base32 characters from the first 20 bits of the account ID,
/// shown in the passkey picker so users can tell accounts apart.
fn short_label(account_id: &[u8; 16]) -> String {
    let bits = (u32::from(account_id[0]) << 12)
        | (u32::from(account_id[1]) << 4)
        | (u32::from(account_id[2]) >> 4);
    (0..4)
        .rev()
        .map(|i| char::from(CROCKFORD[((bits >> (i * 5)) & 0x1f) as usize]))
        .collect()
}

/// `PublicKeyCredentialCreationOptionsJSON`.
pub fn creation(
    config: &Config,
    account_id: &[u8; 16],
    challenge: &[u8],
    exclude: &[Vec<u8>],
) -> Value {
    let name = format!("{} · {}", config.rp_name, short_label(account_id));
    json!({
        "rp": { "id": config.rp_id, "name": config.rp_name },
        "user": { "id": b64::encode(account_id), "name": name, "displayName": name },
        "challenge": b64::encode(challenge),
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
            { "type": "public-key", "alg": -257 }
        ],
        "timeout": CEREMONY_TTL * 1000,
        "excludeCredentials": exclude
            .iter()
            .map(|id| json!({ "type": "public-key", "id": b64::encode(id) }))
            .collect::<Vec<_>>(),
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required"
        },
        "attestation": "none",
        "extensions": { "credProps": true }
    })
}

/// `PublicKeyCredentialRequestOptionsJSON`.
pub fn request(config: &Config, challenge: &[u8]) -> Value {
    json!({
        "challenge": b64::encode(challenge),
        "rpId": config.rp_id,
        "timeout": CEREMONY_TTL * 1000,
        "allowCredentials": [],
        "userVerification": "required"
    })
}

#[cfg(test)]
mod tests {
    use super::short_label;

    #[test]
    fn label_is_four_crockford_chars() {
        assert_eq!(short_label(&[0; 16]), "0000");
        assert_eq!(short_label(&[0xff; 16]), "ZZZZ");
        let mut id = [0u8; 16];
        id[0] = 0b0000_1000; // 5-bit groups: 00001 00000 ...
        assert_eq!(short_label(&id), "1000");
    }
}
