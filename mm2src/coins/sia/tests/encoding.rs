use rpc::v1::types::H256;
use crate::sia::encoding::SiaHash;

#[test]
fn test_sia_hash_display() {
    let hash = SiaHash::from(H256::default());

    assert_eq!(format!("{}", hash), "h:0000000000000000000000000000000000000000000000000000000000000000")
}
