use crate::sia::specifier::Specifier;
use crate::sia::spend_policy::{spend_policy_atomic_swap, SpendPolicy, UnlockCondition};
use crate::sia::PublicKey;
use rpc::v1::types::H256;

// Helper macro for testing successful deserialization
macro_rules! test_deser_success {
    ($type:ty, $value:expr, $expected:expr) => {
        assert_eq!(
            serde_json::from_str::<$type>(&serde_json::json!($value).to_string()).unwrap(),
            $expected
        );
    };
}

// Helper macro for testing expected deserialization errors
macro_rules! test_deser_err {
    ($type:ty, $value:expr, $expected_err:expr) => {
        let result = serde_json::from_str::<$type>(&serde_json::json!($value).to_string());

        assert!(result.is_err());

        if let Err(err) = result {
            assert!(
                err.to_string().contains($expected_err),
                "Error message did not contain expected substring: {}",
                err
            );
        }
    };
}

#[test]
fn test_deser_spend_policy_above() {
    let test_cases = [
        ("above(100000)", SpendPolicy::Above(100000)),
        ("above(0)", SpendPolicy::Above(0)),
        (&format!("above({})", u64::MAX), SpendPolicy::Above(u64::MAX)),
    ];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}

#[test]
fn test_deser_spend_policy_above_expected_failures() {
    fn expected(value: &str) -> String {
        format!(
            "invalid value: string \"{}\", expected a string representing a Sia spend policy",
            value
        )
    }

    let test_cases = [
        "above()",
        &format!("above({})", u128::MAX),
        "above(",
        "above",
        "above(0x10)",
        "above(0x)",
        "above(-1)",
    ];

    for &value in &test_cases {
        test_deser_err!(SpendPolicy, value, &expected(value));
    }
}

#[test]
fn test_deser_spend_policy_after() {
    let test_cases = [
        ("after(100000)", SpendPolicy::After(100000)),
        ("after(0)", SpendPolicy::After(0)),
        (&format!("after({})", u64::MAX), SpendPolicy::After(u64::MAX)),
    ];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}

#[test]
fn test_deser_spend_policy_after_expected_failures() {
    fn expected(value: &str) -> String {
        format!(
            "invalid value: string \"{}\", expected a string representing a Sia spend policy",
            value
        )
    }

    let test_cases = [
        "after()",
        &format!("after({})", u128::MAX),
        "after(",
        "after",
        "after(0x10)",
        "after(0x)",
        "after(-1)",
    ];

    for &value in &test_cases {
        test_deser_err!(SpendPolicy, value, &expected(value));
    }
}

#[test]
fn test_deser_spend_policy_opaque() {
    let test_cases = [(
        "opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)",
        SpendPolicy::Opaque(H256::from(
            "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
        )),
        (
            "opaque( 0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)",
            SpendPolicy::Opaque(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            r"opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d) 
        ",
            SpendPolicy::Opaque(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            r"opaque(
            0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d
        )",
            SpendPolicy::Opaque(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            "opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d\t)",
            SpendPolicy::Opaque(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
    )];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}

#[test]
fn test_deser_spend_policy_opaque_expected_failures() {
    fn expected(value: &str) -> String {
        format!(
            "invalid value: string \"{}\", expected a string representing a Sia spend policy",
            value
        )
    }

    let test_cases = [
        "opaque()",
        "opaque(",
        "opaque",
        "opaque(0x10)",
        "opaque(-1)",
        "opaque(0xbadhex)",
        "opaque(f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)", // no 0x
        "opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0)", // too short
        "opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0eeff)", // too long
    ];

    for &value in &test_cases {
        test_deser_err!(SpendPolicy, value, &expected(value));
    }
}

#[test]
fn test_deser_spend_policy_hash() {
    let test_cases = [(
        "h(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)",
        SpendPolicy::Hash(H256::from(
            "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
        )),
        (
            "h( 0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)",
            SpendPolicy::Hash(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            r"h(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d) 
        ",
            SpendPolicy::Hash(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            r"h(
            0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d
        )",
            SpendPolicy::Hash(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
        (
            "h(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d\t)",
            SpendPolicy::Hash(H256::from(
                "f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d",
            )),
        ),
    )];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}

#[test]
fn test_deser_spend_policy_hash_expected_failures() {
    fn expected(value: &str) -> String {
        format!(
            "invalid value: string \"{}\", expected a string representing a Sia spend policy",
            value
        )
    }

    let test_cases = [
        "h()",
        "h(",
        "h",
        "h(0x10)",
        "h(-1)",
        "h(0xbadhex)",
        "h(f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)", // no 0x
        "h(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0)", // too short
        "h(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0eeff)", // too long
    ];

    for &value in &test_cases {
        test_deser_err!(SpendPolicy, value, &expected(value));
    }
}

#[test]
fn test_deser_spend_policy_public_key() {
    let spend_policy = SpendPolicy::PublicKey(
        PublicKey::from_bytes(
            &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
        )
        .unwrap(),
    );

    let test_cases = [
        (
            "pk(0x0102030000000000000000000000000000000000000000000000000000000000)",
            spend_policy.clone(),
        ),
        (
            "pk( 0x0102030000000000000000000000000000000000000000000000000000000000)",
            spend_policy.clone(),
        ),
        (
            "pk(0x0102030000000000000000000000000000000000000000000000000000000000)\n",
            spend_policy.clone(),
        ),
    ];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}

#[test]
fn test_deser_spend_policy_public_key_expected_failures() {
    fn expected(value: &str) -> String {
        format!(
            "invalid value: string \"{}\", expected a string representing a Sia spend policy",
            value
        )
    }

    let test_cases = [
        "pk()",
        "pk(",
        "pk",
        "pk(0x10)",
        "pk(-1)",
        "pk(0xbadhex)",
        "pk(0102030000000000000000000000000000000000000000000000000000000000)", // no 0x
        "pk(0x01020300000000000000000000000000000000000000000000000000000000)", // too short
        "pk(0x0102030000000000000000000000000000000000000000000000000000000000ff)", // too long
    ];

    for &value in &test_cases {
        test_deser_err!(SpendPolicy, value, &expected(value));
    }
}

#[test]
#[ignore] // FIXME Sia devs just changed this encoding https://github.com/SiaFoundation/core/pull/173
fn test_deser_spend_policy_unlock_condition() {
    let public_key = PublicKey::from_bytes(
        &hex::decode("0102030000000000000000000000000000000000000000000000000000000000").unwrap(),
    )
    .unwrap();

    let test_cases = [(
        "uc(0,[0x0102030000000000000000000000000000000000000000000000000000000000],1)",
        SpendPolicy::UnlockConditions(UnlockCondition::standard_unlock(public_key)),
    )];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}