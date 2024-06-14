use std::collections::BTreeMap;

use crate::{decode_seed, err, from_public_key, KeyPair, KeyPairType, Result};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

// We hard code the value here, because we're using Edwards-curve keys, which OKP represents:
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-cfrg-curves-06#section-2
const JWK_KEY_TYPE: &str = "OKP";
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-cfrg-curves-06#section-3.1
const JWK_ALGORITHM: &str = "EdDSA";
const JWK_SUBTYPE: &str = "Ed25519";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Intended use of the JWK, this is based on the KeyPairType of the KeyPair the JWK is based on, using "enc" for KeyPairType::Curve, otherwise "sig"
    #[serde(rename = "use")]
    intended_use: String,
    /// Key type, which we default to OKP (Octet Key Pair) to represent Edwards-curve keys
    #[serde(rename = "kty")]
    key_type: String,
    /// Key ID, which will be represented by the thumbprint calculated over the subtype (crv), key_type (kty) and public_key (x) components of the JWK.
    /// See https://datatracker.ietf.org/doc/html/rfc7639 for more details.
    #[serde(rename = "kid")]
    key_id: String,
    /// Algorithm used for the JWK, defaults to EdDSA
    #[serde(rename = "alg")]
    algorithm: String,
    /// Subtype of the key (from the "JSON Web Elliptic Curve" registry)
    #[serde(rename = "crv")]
    subtype: String,
    // Public key value encoded using base64url encoding
    #[serde(rename = "x")]
    public_key: String,
    // Private key value, if provided, encoded using base64url encoding
    #[serde(rename = "d", skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

impl JsonWebKey {
    pub fn from_seed(source: &str) -> Result<Self> {
        let (prefix, seed) = decode_seed(source)?;
        let sk = SigningKey::from_bytes(&seed);
        let kp_type = &KeyPairType::from(prefix);
        let public_key = BASE64URL_NOPAD.encode(sk.verifying_key().as_bytes());
        let thumbprint = Self::calculate_thumbprint(&public_key)?;

        Ok(JsonWebKey {
            intended_use: Self::intended_use_for_key_pair_type(kp_type),
            key_id: thumbprint,
            public_key,
            private_key: Some(BASE64URL_NOPAD.encode(sk.as_bytes())),
            ..Default::default()
        })
    }

    pub fn from_public_key(source: &str) -> Result<Self> {
        let (prefix, bytes) = from_public_key(source)?;
        let vk = VerifyingKey::from_bytes(&bytes)?;
        let public_key = BASE64URL_NOPAD.encode(vk.as_bytes());
        let thumbprint = Self::calculate_thumbprint(&public_key)?;

        Ok(JsonWebKey {
            intended_use: Self::intended_use_for_key_pair_type(&KeyPairType::from(prefix)),
            key_id: thumbprint,
            public_key,
            ..Default::default()
        })
    }

    fn intended_use_for_key_pair_type(typ: &KeyPairType) -> String {
        match typ {
            KeyPairType::Server
            | KeyPairType::Cluster
            | KeyPairType::Operator
            | KeyPairType::Account
            | KeyPairType::User
            | KeyPairType::Module
            | KeyPairType::Service => "sig".to_owned(),
            KeyPairType::Curve => "enc".to_owned(),
        }
    }

    /// For details on how fingerprints are calculated, see: https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    /// For OKP specific details, see https://datatracker.ietf.org/doc/html/draft-ietf-jose-cfrg-curves-06#appendix-A.3
    pub fn calculate_thumbprint(public_key: &str) -> Result<String> {
        // We use BTreeMap here, because the order needs to be lexicographically sorted:
        // https://datatracker.ietf.org/doc/html/rfc7638#section-3.3
        let components = BTreeMap::from([
            ("crv", JWK_SUBTYPE),
            ("kty", JWK_KEY_TYPE),
            ("x", public_key),
        ]);
        let value = json!(components);
        let mut bytes: Vec<u8> = Vec::new();
        serde_json::to_writer(&mut bytes, &value).map_err(|_| {
            err!(
                ThumbprintCalculationFailure,
                "unable to serialize public key"
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&*bytes);
        let hash = hasher.finalize();
        Ok(BASE64URL_NOPAD.encode(&hash))
    }
}

impl Default for JsonWebKey {
    fn default() -> Self {
        Self {
            intended_use: Default::default(),
            key_type: JWK_KEY_TYPE.to_string(),
            key_id: Default::default(),
            algorithm: JWK_ALGORITHM.to_string(),
            subtype: JWK_SUBTYPE.to_string(),
            public_key: Default::default(),
            private_key: None,
        }
    }
}

impl TryFrom<KeyPair> for JsonWebKey {
    type Error = crate::error::Error;

    fn try_from(value: KeyPair) -> Result<Self> {
        if let Ok(seed) = value.seed() {
            Ok(Self::from_seed(&seed)?)
        } else {
            Ok(Self::from_public_key(&value.public_key())?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Using the example values from https://datatracker.ietf.org/doc/html/draft-ietf-jose-cfrg-curves-06#appendix-A.3
    #[test]
    fn calculate_thumbprint_provides_correct_thumbprint() {
        let input_public_key = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let expected_thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
        let actual_thumbprint = JsonWebKey::calculate_thumbprint(input_public_key).unwrap();

        assert_eq!(expected_thumbprint, actual_thumbprint);
    }
}
