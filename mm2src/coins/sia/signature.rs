use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

// This wrapper allows us to use Signature internally but still serde as "sig:" prefixed string
#[derive(Debug)]
pub struct SiaSignature(pub Signature);

impl<'de> Deserialize<'de> for SiaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SiaSignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SiaSignatureVisitor {
            type Value = SiaSignature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string prefixed with 'sig:' and followed by a 128-character hex string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Some(hex_str) = value.strip_prefix("sig:") {
                    Signature::from_str(hex_str)
                        .map(SiaSignature)
                        .map_err(|_| E::invalid_value(
                            serde::de::Unexpected::Str(value),
                            &self,
                        ))
                } else {
                    Err(E::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    ))
                }
            }
        }

        deserializer.deserialize_str(SiaSignatureVisitor)
    }
}

impl Serialize for SiaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl fmt::Display for SiaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "h:{}", self.0) }
}


impl From<SiaSignature> for Signature {
    fn from(sia_hash: SiaSignature) -> Self {
        sia_hash.0
    }
}

impl From<Signature> for SiaSignature {
    fn from(signature: Signature) -> Self {
        SiaSignature(signature)
    }
}