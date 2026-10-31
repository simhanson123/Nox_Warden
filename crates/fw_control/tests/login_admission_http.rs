//! Actual signatures through the controller's public login boundary.
#[allow(dead_code)]
#[path = "../../fw_authority/tests/support/approval_authenticator.rs"]
mod authenticator;

use authenticator::{Authenticator, ORIGIN};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use fw_control::{AppState, PRINCIPAL, router};
use fw_store::Store;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn post(
    app: &Router,
    path: &str,
    cookie: &str,
    csrf: &str,
    value: Value,
) -> (u16, String, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1{path}"))
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(';').next().unwrap().to_owned())
        .unwrap_or_default();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 262144).await.unwrap()).unwrap();
    (status, cookie, body)
}

async fn pending_owner() -> (Router, Authenticator) {
    let state = Arc::new(
        AppState::new(
            Store::in_memory().unwrap(),
            ORIGIN.into(),
            "test-console-token",
        )
        .unwrap(),
    );
    let app = router(state, "/tmp/absent-login-test-web".into());
    let (status, cookie, body) = post(
        &app,
        "/session/bootstrap",
        "",
        "",
        json!({"token":"test-console-token"}),
    )
    .await;
    assert_eq!(status, 200);
    let csrf = body["data"]["csrf_token"].as_str().unwrap();
    let (status, _, body) = post(
        &app,
        "/auth/passkeys/registration/options",
        &cookie,
        csrf,
        json!({"name":"Owner"}),
    )
    .await;
    assert_eq!(status, 200);
    let key = Authenticator::new(PRINCIPAL);
    let proof = key.registration(&json!({"publicKey":body["data"]["public_key"]}));
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/registration/complete",
        &cookie,
        csrf,
        json!({"ceremony_id":body["data"]["ceremony_id"],"credential":proof}),
    )
    .await;
    assert_eq!(status, 200);
    (app, key)
}

#[tokio::test]
async fn anonymous_option_flood_cannot_starve_a_pending_owner_login() {
    let (app, key) = pending_owner().await;
    let (status, binding, victim) =
        post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    assert_eq!(status, 200);
    for request in 0..1005 {
        let (status, _, _) = post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
        assert_eq!(
            status, 200,
            "anonymous request {request} exhausted a shared budget"
        );
    }
    let proof = key.assertion(
        &json!({"publicKey":victim["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let (status, session, body) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":victim["data"]["ceremony_id"],"credential":proof}),
    )
    .await;
    assert_eq!(
        status, 200,
        "an earlier valid proof must survive unrelated issuance"
    );
    assert_eq!(body["data"]["authentication_method"], "passkey");
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/registration/options",
        &session,
        body["data"]["csrf_token"].as_str().unwrap(),
        json!({"name":"Spare"}),
    )
    .await;
    assert_eq!(
        status, 200,
        "public login issuance must not consume authenticated registration quota"
    );
}

#[tokio::test]
async fn altered_ticket_wrong_browser_and_invalid_assertions_cannot_authenticate_or_lock_a_valid_proof()
 {
    let (app, key) = pending_owner().await;
    let (_, binding, body) = post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let ticket = body["data"]["ceremony_id"].as_str().unwrap();
    let proof = key.assertion(
        &json!({"publicKey":body["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/login/complete",
        &format!("fw_auth={}", "f".repeat(64)),
        "",
        json!({"ceremony_id":ticket,"credential":proof}),
    )
    .await;
    assert_eq!(status, 401);
    let mut changed = ticket.as_bytes().to_vec();
    let index = changed.len() / 2;
    changed[index] = if changed[index] == b'A' { b'B' } else { b'A' };
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":String::from_utf8(changed).unwrap(),"credential":proof}),
    )
    .await;
    assert_eq!(status, 401);
    let mut invalid = proof.clone();
    invalid.response.signature = "AA".into();
    for _ in 0..150 {
        let (status, _, _) = post(
            &app,
            "/auth/passkeys/login/complete",
            &binding,
            "",
            json!({"ceremony_id":ticket,"credential":invalid}),
        )
        .await;
        assert_eq!(status, 401);
    }
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":ticket,"credential":proof}),
    )
    .await;
    assert_eq!(
        status, 200,
        "unsigned failures cannot spend the legitimate proof's admission budget"
    );
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":ticket,"credential":proof}),
    )
    .await;
    assert_eq!(
        status, 409,
        "zero-counter assertions still require durable single consumption"
    );
}

#[tokio::test]
async fn concurrent_zero_counter_completion_issues_only_one_session() {
    let (app, key) = pending_owner().await;
    let (_, binding, body) = post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let proof = key.assertion(
        &json!({"publicKey":body["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let request = json!({"ceremony_id":body["data"]["ceremony_id"],"credential":proof});
    let (first, second) = tokio::join!(
        post(
            &app,
            "/auth/passkeys/login/complete",
            &binding,
            "",
            request.clone()
        ),
        post(&app, "/auth/passkeys/login/complete", &binding, "", request),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    assert_eq!(
        [first.1, second.1]
            .iter()
            .filter(|v| v.starts_with("fw_session="))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_valid_ticket_cannot_restore_a_credential_revoked_after_issuance() {
    let (app, owner) = pending_owner().await;
    let (_, binding, options) = post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let proof = owner.assertion(
        &json!({"publicKey": options["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let owner_id = proof.id.clone();
    let (status, owner_session, login) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":options["data"]["ceremony_id"], "credential":proof}),
    )
    .await;
    assert_eq!(status, 200);
    let csrf = login["data"]["csrf_token"].as_str().unwrap();
    let (status, _, registration) = post(
        &app,
        "/auth/passkeys/registration/options",
        &owner_session,
        csrf,
        json!({"name":"Spare"}),
    )
    .await;
    assert_eq!(status, 200);
    let spare = Authenticator::new(PRINCIPAL);
    let proof = spare.registration(&json!({"publicKey": registration["data"]["public_key"]}));
    let spare_id = proof.id.clone();
    let (status, _, _) = post(
        &app,
        "/auth/passkeys/registration/complete",
        &owner_session,
        csrf,
        json!({"ceremony_id":registration["data"]["ceremony_id"], "credential":proof}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, binding, options) = post(
        &app,
        "/auth/passkeys/login/options",
        "",
        "",
        json!({"credential_id":spare_id}),
    )
    .await;
    let proof = spare.assertion(
        &json!({"publicKey": options["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let (status, spare_session, login) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":options["data"]["ceremony_id"], "credential":proof}),
    )
    .await;
    assert_eq!(status, 200);
    let (_, binding, pending) = post(
        &app,
        "/auth/passkeys/login/options",
        "",
        "",
        json!({"credential_id":owner_id}),
    )
    .await;
    let proof = owner.assertion(
        &json!({"publicKey": pending["data"]["public_key"]}),
        0,
        5,
        ORIGIN,
    );
    let (status, _, _) = post(
        &app,
        &format!("/auth/passkeys/{owner_id}/revocations"),
        &spare_session,
        login["data"]["csrf_token"].as_str().unwrap(),
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, session, _) = post(
        &app,
        "/auth/passkeys/login/complete",
        &binding,
        "",
        json!({"ceremony_id":pending["data"]["ceremony_id"], "credential":proof}),
    )
    .await;
    assert_eq!(status, 401);
    assert!(session.is_empty());
}

#[tokio::test]
async fn an_older_ticket_cannot_roll_back_an_advanced_signature_counter() {
    let (app, key) = pending_owner().await;
    let (_, first_binding, first) =
        post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let (_, second_binding, second) =
        post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let proof = key.assertion(
        &json!({"publicKey": first["data"]["public_key"]}),
        1,
        5,
        ORIGIN,
    );
    assert_eq!(
        post(
            &app,
            "/auth/passkeys/login/complete",
            &first_binding,
            "",
            json!({"ceremony_id":first["data"]["ceremony_id"], "credential":proof})
        )
        .await
        .0,
        200
    );
    let stale = key.assertion(
        &json!({"publicKey": second["data"]["public_key"]}),
        2,
        5,
        ORIGIN,
    );
    assert_eq!(
        post(
            &app,
            "/auth/passkeys/login/complete",
            &second_binding,
            "",
            json!({"ceremony_id":second["data"]["ceremony_id"], "credential":stale})
        )
        .await
        .0,
        401
    );
    let (_, binding, fresh) = post(&app, "/auth/passkeys/login/options", "", "", json!({})).await;
    let proof = key.assertion(
        &json!({"publicKey": fresh["data"]["public_key"]}),
        2,
        5,
        ORIGIN,
    );
    assert_eq!(
        post(
            &app,
            "/auth/passkeys/login/complete",
            &binding,
            "",
            json!({"ceremony_id":fresh["data"]["ceremony_id"], "credential":proof})
        )
        .await
        .0,
        200
    );
}

#[tokio::test]
async fn encrypted_login_envelope_preserves_all_public_body_limits() {
    let (app, _) = pending_owner().await;
    let padded = format!("{{}}{}", " ".repeat(65536));
    for (path, expected) in [
        ("/auth/passkeys/login/options", 413),
        ("/auth/passkeys/login/complete", 413),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1{path}"))
                    .header("origin", ORIGIN)
                    .header("content-type", "application/json")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .header("cookie", format!("fw_auth={}", "a".repeat(64)))
                    .body(Body::from(padded.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{path}");
    }
    let response = app
        .oneshot(
            Request::post("/api/v1/auth/passkeys/login/complete")
                .body(Body::from(vec![b' '; 65536 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 413);
}
