#[allow(unused_imports)]
use blake2b_simd::{blake2b as _, Params};
use hex::FromHexError;
use rpc::v1::types::H256;
use std::convert::TryInto;
//use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq)]

struct Address(H256);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let checksum = blake2b_checksum(&self.0 .0.to_vec());
        write!(f, "addr:{}{}", self.0, hex::encode(checksum))
    }
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "Failed to parse Address: {:?}", self.kind) }
}

#[derive(Debug)]
struct ParseAddressError {
    kind: ParseAddressErrorKind,
}

#[derive(Debug)]
enum ParseAddressErrorKind {
    InvalidFormat,
    InvalidHexEncoding(FromHexError),

    InvalidChecksum,
    // Add other error kinds as needed
}

//impl Error for ParseAddressError {}

impl From<FromHexError> for ParseAddressError {
    fn from(e: FromHexError) -> Self {
        ParseAddressError {
            kind: ParseAddressErrorKind::InvalidHexEncoding(e),
        }
    }
}

impl FromStr for Address {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("addr:") {
            return Err(ParseAddressError {
                kind: ParseAddressErrorKind::InvalidFormat,
            });
        }

        let without_prefix = &s[5..];
        if without_prefix.len() != (32 + 6) * 2 {
            return Err(ParseAddressError {
                kind: ParseAddressErrorKind::InvalidFormat,
            });
        }

        let (address_hex, checksum_hex) = without_prefix.split_at(32 * 2);

        let address_bytes: [u8; 32] = hex::decode(address_hex)
            .map_err(ParseAddressError::from)?
            .try_into()
            .expect("length is 32 bytes");

        let checksum = hex::decode(checksum_hex).map_err(ParseAddressError::from)?;
        let checksum_bytes: [u8; 6] = checksum.try_into().expect("length is 6 bytes");

        if checksum_bytes != blake2b_checksum(&address_bytes) {
            return Err(ParseAddressError {
                kind: ParseAddressErrorKind::InvalidChecksum,
            });
        }

        Ok(Address(H256::from(address_bytes)))
    }
}

// Sia uses the first 6 bytes of blake2b(preimage) appended
// to address as checksum
fn blake2b_checksum(preimage: &[u8]) -> [u8; 6] {
    let hash = Params::new().hash_length(32).to_state().update(&preimage).finalize();
    hash.as_array()[0..6].try_into().expect("array is 64 bytes long")
}


#[test]
fn test_blake2b_checksum() {
    let checksum = blake2b_checksum(&hex::decode("591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a884").unwrap());
    let expected: [u8; 6] = hex::decode("0be0653e411f").unwrap().try_into().unwrap();
    assert_eq!(checksum, expected);
}

#[test]
fn test_address_display() {
    let address = Address("591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a884".into());
    let address_str = "addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f";
    assert_eq!(format!("{}", address), address_str);
}

#[test]
fn test_address_fromstr() {
    let address1 = Address("591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a884".into());

    let address2 =
        Address::from_str("addr:591fcf237f8854b5653d1ac84ae4c107b37f148c3c7b413f292d48db0c25a8840be0653e411f").unwrap();
    assert_eq!(address1, address2);
}

#[test]
fn test_address_fromstr_bad_length() {

    let address =
        Address::from_str("addr:dead").unwrap();

    assert!(matches!(result, Err(ParseAddressError::BuildError(_))));
}