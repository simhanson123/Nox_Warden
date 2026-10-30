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
                "http://127.0.0.1:8787".into(),
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
                .header("origin", "http://127.0.0.1:8787")
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
        .header("origin", "http://127.0.0.1:8787")
        .body(Body::from(body))
        .unwrap()
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
    let (cookie, _) = login(&app).await;
    let r = app
        .clone()
        .oneshot(
            Request::get("/api/v1/status")
                .header("cookie", cookie)
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
                .header("origin", "http://127.0.0.1:8787")
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
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
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
