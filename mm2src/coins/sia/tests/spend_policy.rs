use rpc::v1::types::H256;

use crate::sia::spend_policy::SpendPolicy;
use crate::sia::address::Address;

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
        (&format!("above({})", u64::MAX), SpendPolicy::Above(u64::MAX))
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
        (&format!("after({})", u64::MAX), SpendPolicy::After(u64::MAX))
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
    let test_cases = [
        ("opaque(0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)", SpendPolicy::Opaque(H256::from("f72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d"))),
    ];

    for value in test_cases {
        test_deser_success!(SpendPolicy, value.0, value.1);
    }
}