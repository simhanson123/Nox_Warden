use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use fw_control::{AppState, router};
use fw_store::Store;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
fn app() -> axum::Router {
    router(
        Arc::new(
            AppState::new(
                Store::in_memory().unwrap(),
                "http://localhost:8787".into(),
                "unit-test-token",
            )
            .unwrap(),
        ),
        "/tmp/nox-web-test-absent".into(),
    )
}
async fn login(app: &axum::Router) -> (String, String) {
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/v1/session/bootstrap")
                .header("origin", "http://localhost:8787")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(r#"{"token":"unit-test-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(
        r.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("HttpOnly")
    );
    let b: Value = serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap();
    (
        cookie,
        b["data"]["csrf_token"].as_str().unwrap().to_string(),
    )
}
fn post(path: &str, cookie: &str, csrf: &str, key: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("idempotency-key", key)
        .header("origin", "http://localhost:8787")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn bootstrap_cookie_alone_cannot_recover_proof_or_begin_owner_registration() {
    let app = app();
    let (cookie, proof) = login(&app).await;
    // A service on another localhost port receives the host-scoped cookie and
    // can send an Origin header itself. Neither fact proves possession of the
    // independently returned bootstrap response kept in browser memory.
    for path in ["/api/v1/session", "/api/v1/status", "/api/v1/auth/passkeys"] {
        for presented in [None, Some("incorrect-proof")] {
            let mut request = Request::get(path)
                .header("cookie", &cookie)
                .header("origin", "http://localhost:8787");
            if let Some(presented) = presented {
                request = request.header("x-csrf-token", presented);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            let body = to_bytes(response.into_body(), 65536).await.unwrap();
            assert!(!String::from_utf8_lossy(&body).contains(&proof));
        }
    }
    let response = app
        .clone()
        .oneshot(post(
            "/api/v1/auth/passkeys/registration/options",
            &cookie,
            "incorrect-proof",
            &Uuid::new_v4().to_string(),
            json!({"name":"Untrusted local service"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The refused cookie probes must not destroy the legitimate setup session.
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/session")
                .header("cookie", &cookie)
                .header("x-csrf-token", &proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(session["data"]["owner_enrolled"], false);
    let response = app
        .oneshot(post(
            "/api/v1/auth/passkeys/registration/options",
            &cookie,
            &proof,
            &Uuid::new_v4().to_string(),
            json!({"name":"Initial owner"}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_reads_and_single_use_bootstrap() {
    let app = app();
    let r = app
        .clone()
        .oneshot(Request::get("/api/v1/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let (cookie, csrf) = login(&app).await;
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/status")
                .header("cookie", cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b: Value = serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(b["data"]["enforcement"], false);
    let r = app
        .oneshot(
            Request::post("/api/v1/session/bootstrap")
                .header("origin", "http://localhost:8787")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(r#"{"token":"unit-test-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn csrf_and_native_admission_are_enforced() {
    let app = app();
    let (cookie, csrf) = login(&app).await;
    let key = Uuid::new_v4().to_string();
    let r = app
        .clone()
        .oneshot(post(
            "/api/v1/deployments",
            &cookie,
            "incorrect",
            &key,
            "{}".into(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = app
        .oneshot(post(
            "/api/v1/deployments",
            &cookie,
            &csrf,
            &key,
            "{}".into(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
#[tokio::test]
async fn strict_json_rejects_duplicate_and_unknown_fields() {
    let app = app();
    let (cookie, csrf) = login(&app).await;
    let key = Uuid::new_v4().to_string();
    for body in [r#"{"purpose":"one","purpose":"two"}"#, r#"{"admin":true}"#] {
        let r = app
            .clone()
            .oneshot(post(
                "/api/v1/access-requests",
                &cookie,
                &csrf,
                &key,
                body.into(),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
}
#[tokio::test]
async fn request_idempotency_persists_without_authorizing_network() {
    let app = app();
    let (cookie, csrf) = login(&app).await;
    let key = Uuid::new_v4().to_string();
    let body = json!({"schema_version":"f.access-request/v1","idempotency_key":key,"workflow_id":"test","workload_binding_id":Uuid::new_v4(),"source_asset_ids":[Uuid::new_v4()],"destination_asset_ids":[Uuid::new_v4()],"service_id":"https","lease_seconds":60,"purpose":"integration test"});
    let mut request_id = String::new();
    for _ in 0..2 {
        let r = app
            .clone()
            .oneshot(post(
                "/api/v1/access-requests",
                &cookie,
                &csrf,
                &key,
                body.to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        let b: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap();
        let id = b["data"]["resource_id"].as_str().unwrap();
        if request_id.is_empty() {
            request_id = id.into();
        } else {
            assert_eq!(request_id, id);
        }
    }
    let r = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/access-requests/{request_id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b: Value = serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(b["data"]["state"], "needs_info");
    let mut changed = body;
    changed["purpose"] = json!("changed");
    let r = app
        .oneshot(post(
            "/api/v1/access-requests",
            &cookie,
            &csrf,
            &key,
            changed.to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn body_limit_rejects_oversize() {
    let app = app();
    let (cookie, csrf) = login(&app).await;
    let r = app
        .oneshot(post(
            "/api/v1/access-requests",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            "x".repeat(65537),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
