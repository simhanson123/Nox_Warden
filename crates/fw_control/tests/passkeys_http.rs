use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use fw_control::{AppState, ORG, PRINCIPAL, PROJECT, router};
use fw_store::{
    Store, Tenant,
    passkeys::{PasskeyAuthority, PasskeyChallengeInput, VerifiedPasskey},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "http://localhost:8787";
fn app(origin: &str) -> (Arc<AppState>, Router) {
    let state = Arc::new(
        AppState::new(
            Store::in_memory().unwrap(),
            origin.into(),
            "test-console-secret",
        )
        .unwrap(),
    );
    let app = router(state.clone(), "/tmp/fw-absent-web".into());
    (state, app)
}
async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}
async fn bootstrap(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/session/bootstrap")
                .header("origin", ORIGIN)
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(
                    json!({"token":"test-console-secret"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let value = body(response).await;
    assert_eq!(value["data"]["authentication_method"], "bootstrap");
    (
        cookie,
        value["data"]["csrf_token"].as_str().unwrap().to_owned(),
    )
}
fn post(path: &str, cookie: &str, csrf: &str, key: &str, value: Value) -> Request<Body> {
    Request::post(path)
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("idempotency-key", key)
        .body(Body::from(value.to_string()))
        .unwrap()
}
#[tokio::test]
async fn status_exposes_origin_support_without_claiming_enforcement() {
    for (origin, available) in [(ORIGIN, true), ("http://127.0.0.1:8787", false)] {
        let (_, app) = app(origin);
        let response = app
            .oneshot(
                Request::get("/api/v1/auth/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let value = body(response).await;
        assert_eq!(value["data"]["passkey_available"], available);
        assert_eq!(value["data"]["owner_enrolled"], false);
        assert_eq!(value["data"]["bootstrap_available"], true);
    }
}
#[tokio::test]
async fn registration_options_require_session_csrf_and_have_required_verification() {
    let (_, app) = app(ORIGIN);
    let path = "/api/v1/auth/passkeys/registration/options";
    let response = app
        .clone()
        .oneshot(post(
            path,
            "",
            "",
            &Uuid::new_v4().to_string(),
            json!({"name":"Security key"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (cookie, csrf) = bootstrap(&app).await;
    let response = app
        .clone()
        .oneshot(post(
            path,
            &cookie,
            "wrong",
            &Uuid::new_v4().to_string(),
            json!({"name":"Security key"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let key = Uuid::new_v4().to_string();
    let first = app
        .clone()
        .oneshot(post(
            path,
            &cookie,
            &csrf,
            &key,
            json!({"name":"Security key"}),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = body(first).await;
    assert_eq!(
        first["data"]["public_key"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(first["data"].get("state").is_none());
    assert!(
        first["data"]["public_key"]["challenge"]
            .as_str()
            .unwrap()
            .len()
            >= 43
    );
    let again = body(
        app.clone()
            .oneshot(post(
                path,
                &cookie,
                &csrf,
                &key,
                json!({"name":"Security key"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first["data"], again["data"]);
    let conflict = app
        .oneshot(post(
            path,
            &cookie,
            &csrf,
            &key,
            json!({"name":"Other key"}),
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn forged_registration_does_not_enroll_owner_or_create_session() {
    let (state, app) = app(ORIGIN);
    let (cookie, csrf) = bootstrap(&app).await;
    let options = body(
        app.clone()
            .oneshot(post(
                "/api/v1/auth/passkeys/registration/options",
                &cookie,
                &csrf,
                &Uuid::new_v4().to_string(),
                json!({"name":"Security key"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let proof = json!({"ceremony_id":options["data"]["ceremony_id"],"credential":{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"AA"},"clientExtensionResults":{}}});
    let response = app
        .clone()
        .oneshot(post(
            "/api/v1/auth/passkeys/registration/complete",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            proof,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("set-cookie").is_none());
    assert_eq!(
        body(response).await["detail"],
        "PASSKEY_VERIFICATION_FAILED"
    );
    assert!(
        !state
            .store
            .passkey_owner_enrolled(&Tenant::new(ORG, PROJECT).unwrap(), PRINCIPAL)
            .unwrap()
    );
    let list = body(
        app.oneshot(
            Request::get("/api/v1/auth/passkeys")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(list["data"]["credentials"], json!([]));
}
#[tokio::test]
async fn pending_owner_rejects_existing_bootstrap_session_and_token() {
    let (state, app) = app(ORIGIN);
    let (cookie, _csrf) = bootstrap(&app).await;
    let tenant = Tenant::new(ORG, PROJECT).unwrap();
    let at = chrono::Utc::now().timestamp();
    let binding = fw_contracts::hash_bytes(b"explicit unit test storage fixture");
    let saved = state
        .store
        .begin_passkey_challenge(
            &tenant,
            PRINCIPAL,
            &PasskeyChallengeInput {
                kind: "registration".into(),
                session_binding: binding.clone(),
                authority: Some(PasskeyAuthority::Bootstrap),
                name: Some("Test storage fixture".into()),
                request: json!({}),
                options: json!({}),
                state: json!({}),
            },
            &Uuid::new_v4().to_string(),
            at,
        )
        .unwrap();
    // This test isolates the HTTP bootstrap boundary. Real cryptography is
    // exercised by fw_webauthn and the browser smoke, not this storage callback.
    state
        .store
        .finish_passkey_challenge(
            &tenant,
            PRINCIPAL,
            &saved.challenge_id,
            "registration",
            &binding,
            &json!({}),
            &Uuid::new_v4().to_string(),
            at,
            |_, _| {
                Ok(VerifiedPasskey {
                    credential_id: "dGVzdA".into(),
                    credential: json!({"unit_test":"opaque credential"}),
                })
            },
        )
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/status")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/session/bootstrap")
                .header("origin", ORIGIN)
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(
                    json!({"token":"test-console-secret"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let status = body(
        app.oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status["data"]["owner_enrolled"], true);
    assert_eq!(status["data"]["bootstrap_available"], false);
}
#[tokio::test]
async fn login_is_origin_bound_and_logout_cannot_skip_csrf() {
    let (_, app) = app(ORIGIN);
    let mut request = post(
        "/api/v1/auth/passkeys/login/options",
        "",
        "",
        &Uuid::new_v4().to_string(),
        json!({}),
    );
    request
        .headers_mut()
        .insert("origin", "http://evil.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let (cookie, csrf) = bootstrap(&app).await;
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/api/v1/auth/logout",
                &cookie,
                "wrong",
                &Uuid::new_v4().to_string(),
                json!({})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = app
        .clone()
        .oneshot(post(
            "/api/v1/auth/logout",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        app.oneshot(
            Request::get("/api/v1/session")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
}
