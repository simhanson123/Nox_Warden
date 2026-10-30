use fw_contracts::{
    canonical_bytes, canonical_hash, parse_strict, parse_value, Counter, MAX_BODY_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Closed {
    count: Counter,
}

#[test]
fn duplicate_keys_cannot_choose_first_or_last_authority() {
    for input in [
        r#"{"approved":false,"approved":true}"#,
        r#"{"outer":{"x":1,"x":2}}"#,
        r#"{"x":1,"\u0078":2}"#,
    ] {
        assert!(parse_value(input.as_bytes()).is_err(), "{input}");
    }
}

#[test]
fn float_nonfinite_unsafe_and_malformed_numbers_are_rejected() {
    for input in [
        "1.0",
        "1e0",
        "-0.0",
        "NaN",
        "Infinity",
        "-Infinity",
        "9007199254740992",
        "-9007199254740992",
        "01",
        "+1",
    ] {
        assert!(parse_value(input.as_bytes()).is_err(), "{input}");
    }
    assert!(parse_value(b"9007199254740991").is_ok());
    assert!(parse_value(b"-9007199254740991").is_ok());
}

#[test]
fn admission_limits_utf8_depth_size_and_trailing_documents() {
    assert!(parse_value(&[b'"', 0xff, b'"']).is_err());
    assert!(parse_value(br#""\ud800""#).is_err());
    assert!(parse_value(b"{} {}").is_err());
    assert!(parse_value(format!("{}0{}", "[".repeat(32), "]".repeat(32)).as_bytes()).is_ok());
    assert!(parse_value(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
    let boundary = format!("\"{}\"", "a".repeat(MAX_BODY_BYTES - 2));
    assert!(parse_value(boundary.as_bytes()).is_ok());
    assert!(parse_value(format!("{boundary} ").as_bytes()).is_err());
}

#[test]
fn unknown_fields_are_rejected_by_closed_domain_type() {
    assert_eq!(
        parse_strict::<Closed>(br#"{"count":"7"}"#).unwrap().count,
        Counter(7)
    );
    assert!(parse_strict::<Closed>(br#"{"count":"7","admin":true}"#).is_err());
    assert!(parse_strict::<Closed>(br#"{"count":7}"#).is_err());
}

#[test]
fn counter_is_canonical_u64_and_overflow_never_wraps() {
    assert_eq!(
        Counter::parse("18446744073709551615").unwrap(),
        Counter(u64::MAX)
    );
    assert!(Counter(u64::MAX).checked_next().is_err());
    for value in [
        "18446744073709551616",
        "01",
        "00",
        "-1",
        "+1",
        "1.0",
        " 1",
        "",
    ] {
        assert!(Counter::parse(value).is_err());
    }
    assert_eq!(
        serde_json::to_string(&Counter(u64::MAX)).unwrap(),
        r#""18446744073709551615""#
    );
}

#[test]
fn canonical_golden_preserves_unicode_and_array_order() {
    let value = json!({"z":[2,1],"a":"é\n"});
    assert_eq!(
        canonical_bytes(&value).unwrap(),
        "{\"a\":\"é\\n\",\"z\":[2,1]}".as_bytes()
    );
    assert_eq!(
        canonical_hash(&json!({"b":2,"a":1})).unwrap(),
        "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    );
    assert_ne!(
        canonical_hash(&json!({"subject":"é"})).unwrap(),
        canonical_hash(&json!({"subject":"e\u{301}"})).unwrap()
    );
    assert_ne!(
        canonical_hash(&json!([1, 2])).unwrap(),
        canonical_hash(&json!([2, 1])).unwrap()
    );
    assert!(canonical_bytes(&json!({"é":1})).is_err());
    assert!(canonical_bytes(&json!(1.0)).is_err());
    assert!(canonical_bytes(&f64::NAN).is_err());
    assert!(canonical_bytes(&vec![f64::INFINITY]).is_err());
}

#[test]
fn reference_fixture_hashes_match_published_plan_and_grant() {
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    assert_eq!(
        canonical_hash(&bundle["envelope"]).unwrap(),
        bundle["delegation"]["envelope_hash"]
    );
    assert_eq!(
        canonical_hash(&bundle["delegation"]).unwrap(),
        bundle["grant"]["payload"]["delegation_hash"]
    );
}
