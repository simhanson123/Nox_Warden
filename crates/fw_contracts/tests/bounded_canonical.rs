use fw_contracts::{canonical_bytes, canonical_bytes_with_limit, ContractError, MAX_DEPTH};
use serde_json::{json, Value};

#[test]
fn exact_budget_preserves_canonical_bytes_and_counts_json_escapes() {
    let value = json!({"z":[true,null,123],"a":"\n\"\\é"});
    let expected = canonical_bytes(&value).unwrap();
    assert_eq!(
        canonical_bytes_with_limit(&value, expected.len()).unwrap(),
        expected
    );
    assert!(matches!(
        canonical_bytes_with_limit(&value, expected.len() - 1),
        Err(ContractError::BodyTooLarge)
    ));
    assert!(matches!(
        canonical_bytes_with_limit(&json!("x".repeat(1024 * 1024)), 1024),
        Err(ContractError::BodyTooLarge)
    ));
}

#[test]
fn depth_and_float_guards_precede_counting_serialization() {
    let mut value = Value::Null;
    for _ in 0..MAX_DEPTH {
        value = Value::Array(vec![value]);
    }
    let bytes = canonical_bytes_with_limit(&value, 4096).unwrap();
    assert_eq!(bytes, canonical_bytes(&value).unwrap());
    value = Value::Array(vec![value]);
    let error = canonical_bytes_with_limit(&value, 1)
        .unwrap_err()
        .to_string();
    assert!(error.contains("MAX_DEPTH_EXCEEDED"), "{error}");
    for number in [f64::NAN, f64::INFINITY, 1.0] {
        let error = canonical_bytes_with_limit(&number, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("FLOAT_NOT_ALLOWED"), "{error}");
    }
}
