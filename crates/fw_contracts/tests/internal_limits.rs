use fw_contracts::{
    parse_strict, parse_strict_with_limit, ContractError, MAX_BODY_BYTES, MAX_INTERNAL_BYTES,
};
use serde::Deserialize;
use serde_json::Value;

#[test]
fn larger_internal_artifact_does_not_raise_public_body_limit() {
    let body = format!("{{\"data\":\"{}\"}}", "a".repeat(MAX_BODY_BYTES));
    assert!(matches!(
        parse_strict::<Value>(body.as_bytes()),
        Err(ContractError::BodyTooLarge)
    ));
    assert!(parse_strict_with_limit::<Value>(body.as_bytes(), body.len()).is_ok());
    assert!(matches!(
        parse_strict_with_limit::<Value>(body.as_bytes(), body.len() - 1),
        Err(ContractError::BodyTooLarge)
    ));
    assert!(parse_strict_with_limit::<Value>(b"{}", MAX_INTERNAL_BYTES + 1).is_err());
    assert!(parse_strict_with_limit::<Value>(b"{}", 0).is_err());
}

#[test]
fn internal_budget_preserves_strict_syntax_and_closed_types() {
    for bad in [
        br#"{"key":1,"key":2}"#.as_slice(),
        br#"{"value":1.5}"#,
        br#"{"value":9007199254740992}"#,
    ] {
        assert!(parse_strict_with_limit::<Value>(bad, 1024 * 1024).is_err());
    }
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(parse_strict_with_limit::<Value>(deep.as_bytes(), 1024 * 1024).is_err());
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Closed {}
    assert!(parse_strict_with_limit::<Closed>(b"{\"extra\":1}", 1024 * 1024).is_err());
}
