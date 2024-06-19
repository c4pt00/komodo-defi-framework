use crate::sia::encoding::{Encodable, Encoder};

// this macro allows us to define the byte arrays as constants at compile time
macro_rules! define_byte_array_const {
    ($name:ident, $size:expr, $value:expr) => {
        pub const $name: [u8; $size] = {
            let mut arr = [0u8; $size];
            let bytes = $value.as_bytes();
            let mut i = 0;
            while i < bytes.len() && i < $size {
                arr[i] = bytes[i];
                i += 1;
            }
            arr
        };
    };
}

define_byte_array_const!(ED25519, 16, "ed25519");
define_byte_array_const!(SIACOIN_OUTPUT, 16, "siacoin output");
define_byte_array_const!(SIAFUND_OUTPUT, 16, "siafund output");
define_byte_array_const!(FILE_CONTRACT, 16, "file contract");
define_byte_array_const!(STORAGE_PROOF, 16, "storage proof");
define_byte_array_const!(FOUNDATION, 16, "foundation");
define_byte_array_const!(ENTROPY, 16, "entropy");

// https://github.com/SiaFoundation/core/blob/6c19657baf738c6b730625288e9b5413f77aa659/types/types.go#L40-L49
// A Specifier is a fixed-size, 0-padded identifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Specifier {
    identifier: Identifier,
}

impl Specifier {
    pub fn new(identifier: Identifier) -> Self { Specifier { identifier } }
}

impl Encodable for Specifier {
    fn encode(&self, encoder: &mut Encoder) { encoder.write_slice(self.identifier.as_bytes()); }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Identifier {
    Ed25519,
    SiacoinOutput,
    SiafundOutput,
    FileContract,
    StorageProof,
    Foundation,
    Entropy,
}

impl Identifier {
    pub fn as_bytes(&self) -> &'static [u8; 16] {
        match self {
            Identifier::Ed25519 => &ED25519,
            Identifier::SiacoinOutput => &SIACOIN_OUTPUT,
            Identifier::SiafundOutput => &SIAFUND_OUTPUT,
            Identifier::FileContract => &FILE_CONTRACT,
            Identifier::StorageProof => &STORAGE_PROOF,
            Identifier::Foundation => &FOUNDATION,
            Identifier::Entropy => &ENTROPY,
        }
    }
}
