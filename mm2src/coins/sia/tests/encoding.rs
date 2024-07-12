use crate::sia::encoding::PrefixedH256;
use rpc::v1::types::H256;

#[test]
fn test_sia_hash_display() {
    let hash = PrefixedH256::from(H256::default());

    assert_eq!(
        format!("{}", hash),
        "h:0000000000000000000000000000000000000000000000000000000000000000"
    )
}
