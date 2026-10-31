use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use fw_control::{AppState, ORG, PRINCIPAL, PROJECT, router};
use fw_store::{Store, Tenant};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
#[path = "../../fw_store/tests/support/enrolled_target.rs"]
mod enrolled_target;
fn asset(name: &str) -> Value {
    json!({"definition":{"name":name,"asset_kind":"host","owner_id":PRINCIPAL,"addresses":[{"family":"ipv4","cidr":"192.0.2.10/32","interface":null}],"criticality":"normal","isolation":"host","provenance":"manual","source_evidence":null},"state":"active"})
}
fn service(id: &str, asset_id: &str, target: &str) -> Value {
    json!({"service_id":id,"definition":{"name":format!("Service {id}"),"owner_id":PRINCIPAL,"destination_asset_ids":[asset_id],"target_ids":[target],"transport":{"protocol":"tcp","destination_ports":[{"start":443,"end":443}]},"description":"HTTPS catalogue entry","criticality":"normal"}})
}
fn app(store: Store) -> (Router, String) {
    let tenant = store
        .ensure_tenant(ORG, PROJECT, "Local development", 1)
        .unwrap();
    store
        .ensure_principal(&tenant, PRINCIPAL, "human", 1)
        .unwrap();
    let (target, _) =
        enrolled_target::enrolled(&store, &tenant, PRINCIPAL, chrono::Utc::now().timestamp());
    (
        router(
            Arc::new(
                AppState::new(store, "http://127.0.0.1:8787".into(), "registry-test-token")
                    .unwrap(),
            ),
            "/tmp/nox-registry-web-absent".into(),
        ),
        target,
    )
}
async fn decode(response: axum::response::Response) -> (StatusCode, HeaderMap, Value) {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 262144).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap();
    (status, headers, body)
}
async fn login(app: &Router) -> (String, String) {
    let (status, headers, body) = decode(
        app.clone()
            .oneshot(
                Request::post("/api/v1/session/bootstrap")
                    .header("origin", "http://127.0.0.1:8787")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .body(Body::from(r#"{"token":"registry-test-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string(),
        body["data"]["csrf_token"].as_str().unwrap().to_string(),
    )
}
async fn get(app: &Router, path: &str, cookie: &str, csrf: &str) -> (StatusCode, HeaderMap, Value) {
    decode(
        app.clone()
            .oneshot(
                Request::get(path)
                    .header("cookie", cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await
}
async fn post(
    app: &Router,
    path: &str,
    cookie: &str,
    csrf: &str,
    key: &str,
    etag: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::post(path)
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:8787")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("idempotency-key", key);
    if let Some(etag) = etag {
        request = request.header("if-match", etag);
    }
    decode(
        app.clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap(),
    )
    .await
}
#[tokio::test]
async fn asset_revision_and_idempotency_are_real() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    let key = Uuid::new_v4().to_string();
    let (status, headers, created) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &key,
        None,
        asset("Host"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let v = &created["data"];
    assert_eq!(v["schema_version"], "f.asset/v1");
    assert_eq!(v["org_id"], ORG);
    assert_eq!(v["project_id"], PROJECT);
    assert_eq!(v["created_by"], PRINCIPAL);
    assert_eq!(v["revision"], 1);
    assert!(v["previous_revision_hash"].is_null());
    assert_eq!(created["freshness"]["source"], "registry");
    let id = v["asset_id"].as_str().unwrap();
    let etag = headers["etag"].to_str().unwrap();
    assert_eq!(
        etag,
        format!("\"rev-1-{}\"", v["content_hash"].as_str().unwrap())
    );
    let (status, _, replay) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &key,
        None,
        asset("Host"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["data"], created["data"]);
    let (status, _, conflict) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &key,
        None,
        asset("Different"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], "IDEMPOTENCY_CONFLICT");
    let (status, detail_headers, detail) =
        get(&app, &format!("/api/v1/assets/{id}"), &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["data"], created["data"]);
    assert_eq!(detail_headers["etag"], headers["etag"]);
    let (status, _, list) = get(&app, "/api/v1/assets", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert!(list["revision"].as_i64().unwrap() > 0);
}
#[tokio::test]
async fn revisions_require_exact_etag_and_retry_original_revision() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    let (_, headers, created) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("First"),
    )
    .await;
    let id = created["data"]["asset_id"].as_str().unwrap();
    let path = format!("/api/v1/assets/{id}/revisions");
    let etag = headers["etag"].to_str().unwrap();
    let (status, _, body) = post(
        &app,
        &path,
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("Second"),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["code"], "PRECONDITION_REQUIRED");
    for etag in [
        "*",
        "W/\"rev-1-sha256:123\"",
        "\"rev-01-sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
    ] {
        assert_eq!(
            post(
                &app,
                &path,
                &cookie,
                &csrf,
                &Uuid::new_v4().to_string(),
                Some(etag),
                asset("Second")
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let key = Uuid::new_v4().to_string();
    let (status, new_headers, revised) = post(
        &app,
        &path,
        &cookie,
        &csrf,
        &key,
        Some(etag),
        asset("Second"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{revised}");
    assert_eq!(revised["data"]["revision"], 2);
    assert_eq!(
        revised["data"]["previous_revision_hash"],
        created["data"]["content_hash"]
    );
    assert_ne!(headers["etag"], new_headers["etag"]);
    let (status, _, replay) = post(
        &app,
        &path,
        &cookie,
        &csrf,
        &key,
        Some(etag),
        asset("Second"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["data"], revised["data"]);
    let (status, _, body) = post(
        &app,
        &path,
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        Some(etag),
        asset("Third"),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["code"], "REVISION_CONFLICT");
}
#[tokio::test]
async fn catalogue_input_cannot_claim_trusted_identity_or_server_fields() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    let mut trusted = asset("Untrusted");
    trusted["definition"]["provenance"] = json!("enrolled_agent");
    assert_eq!(
        post(
            &app,
            "/api/v1/assets",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            trusted
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut wrong = asset("Wrong");
    wrong["org_id"] = json!(Uuid::new_v4());
    assert_eq!(
        post(
            &app,
            "/api/v1/assets",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            wrong
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for field in ["source_evidence", "interface"] {
        let mut missing = asset("Missing");
        if field == "interface" {
            missing["definition"]["addresses"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
        } else {
            missing["definition"].as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            post(
                &app,
                "/api/v1/assets",
                &cookie,
                &csrf,
                &Uuid::new_v4().to_string(),
                None,
                missing
            )
            .await
            .0,
            StatusCode::BAD_REQUEST,
            "required nullable {field}"
        );
    }
    let mut noncanonical = asset("Host bits");
    noncanonical["definition"]["addresses"][0]["cidr"] = json!("192.0.2.10/24");
    assert_eq!(
        post(
            &app,
            "/api/v1/assets",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            noncanonical
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        post(
            &app,
            "/api/v1/assets",
            &cookie,
            "bad-csrf",
            &Uuid::new_v4().to_string(),
            None,
            asset("CSRF")
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn services_refer_to_existing_assets_and_targets_with_exact_transport() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    let (_, _, created) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("Destination"),
    )
    .await;
    let id = created["data"]["asset_id"].as_str().unwrap();
    let body = service("web.https", id, &_target);
    let key = Uuid::new_v4().to_string();
    let (status, headers, created) = post(
        &app,
        "/api/v1/services",
        &cookie,
        &csrf,
        &key,
        None,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["data"]["service_id"], "web.https");
    assert_eq!(created["data"]["schema_version"], "f.service/v1");
    let (status, _, replay) = post(
        &app,
        "/api/v1/services",
        &cookie,
        &csrf,
        &key,
        None,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replay["data"], created["data"]);
    let (status, _, detail) = get(&app, "/api/v1/services/web.https", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["data"], created["data"]);
    let mut revised = json!({"definition":body["definition"],"state":"active"});
    revised["definition"]["description"] = json!("Updated catalogue description");
    assert_eq!(
        post(
            &app,
            "/api/v1/services/web.https/revisions",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            Some(headers["etag"].to_str().unwrap()),
            revised
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let mut missing = service("missing", id, &_target);
    missing["definition"]["target_ids"] = json!([Uuid::new_v4()]);
    assert_eq!(
        post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            missing
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let mut overlap = service("overlap", id, &_target);
    overlap["definition"]["transport"]["destination_ports"] =
        json!([{"start":443,"end":445},{"start":445,"end":446}]);
    assert_eq!(
        post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            overlap
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut extra = service("extra", id, &_target);
    extra["definition"]["transport"]["type"] = json!(8);
    assert_eq!(
        post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            extra
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn retired_assets_stay_visible_but_cannot_be_reactivated_or_referenced() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    let (_, headers, created) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("Retire"),
    )
    .await;
    let id = created["data"]["asset_id"].as_str().unwrap();
    let path = format!("/api/v1/assets/{id}/revisions");
    let mut retired = asset("Retire");
    retired["state"] = json!("retired");
    let (status, headers, _) = post(
        &app,
        &path,
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        Some(headers["etag"].to_str().unwrap()),
        retired,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, detail) = get(&app, &format!("/api/v1/assets/{id}"), &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["data"]["state"], "retired");
    assert_eq!(detail["actions"][0]["allowed"], false);
    assert_eq!(
        post(
            &app,
            &path,
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            Some(headers["etag"].to_str().unwrap()),
            asset("Retire")
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert_eq!(
        post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            service("retired", id, &_target)
        )
        .await
        .0,
        StatusCode::GONE
    );
}
#[tokio::test]
async fn cross_tenant_objects_are_not_found() {
    let store = Store::in_memory().unwrap();
    let other = Tenant::new(
        "00000000-0000-4000-8000-000000000011",
        "00000000-0000-4000-8000-000000000012",
    )
    .unwrap();
    store
        .ensure_tenant(&other.org_id, &other.project_id, "Other", 1)
        .unwrap();
    store
        .ensure_principal(&other, PRINCIPAL, "human", 1)
        .unwrap();
    let hidden = store
        .create_asset(
            &other,
            PRINCIPAL,
            &asset("Hidden"),
            &Uuid::new_v4().to_string(),
            1,
        )
        .unwrap()
        .value;
    let (app, _target) = app(store);
    let (cookie, csrf) = login(&app).await;
    let hidden_id = hidden["asset_id"].as_str().unwrap();
    assert_eq!(
        get(&app, &format!("/api/v1/assets/{hidden_id}"), &cookie, &csrf)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            service("hidden", hidden_id, &_target)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn bounded_lists_continue_instead_of_failing() {
    let (app, _target) = app(Store::in_memory().unwrap());
    let (cookie, csrf) = login(&app).await;
    for name in ["One", "Two"] {
        assert_eq!(
            post(
                &app,
                "/api/v1/assets",
                &cookie,
                &csrf,
                &Uuid::new_v4().to_string(),
                None,
                asset(name)
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    let (status, _, body) = get(&app, "/api/v1/assets?limit=1", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert!(body["next_cursor"].is_string());
    for query in ["limit=0", "limit=101", "cursor=unknown", "unknown=true"] {
        assert_eq!(
            get(&app, &format!("/api/v1/assets?{query}"), &cookie, &csrf)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
}
#[tokio::test]
async fn collections_over_one_hundred_rows_have_scoped_stable_continuations() {
    let store = Store::in_memory().unwrap();
    let at = chrono::Utc::now().timestamp();
    let tenant = store
        .ensure_tenant(ORG, PROJECT, "Local development", at)
        .unwrap();
    store
        .ensure_principal(&tenant, PRINCIPAL, "human", at)
        .unwrap();
    for n in 0..105 {
        store
            .create_asset(
                &tenant,
                PRINCIPAL,
                &asset(&format!("Asset {n}")),
                &Uuid::new_v4().to_string(),
                at,
            )
            .unwrap();
        store
            .submit_unenrolled_request(
                &tenant,
                PRINCIPAL,
                "access_request",
                &json!({"number":n}),
                &Uuid::new_v4().to_string(),
                at,
            )
            .unwrap();
    }
    let (app, _) = app(store);
    let (cookie, csrf) = login(&app).await;
    for route in ["assets", "access-requests", "operations"] {
        let (status, _, first) = get(&app, &format!("/api/v1/{route}"), &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["data"].as_array().unwrap().len(), 50);
        let (status, _, max) = get(&app, &format!("/api/v1/{route}?limit=100"), &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(max["data"].as_array().unwrap().len(), 100);
        let mut rows = first["data"].as_array().unwrap().clone();
        let mut cursor = first["next_cursor"].as_str().map(str::to_owned);
        while let Some(c) = cursor {
            let (status, _, page) =
                get(&app, &format!("/api/v1/{route}?cursor={c}"), &cookie, &csrf).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            assert_eq!(page["revision"], first["revision"]);
            rows.extend(page["data"].as_array().unwrap().clone());
            cursor = page["next_cursor"].as_str().map(str::to_owned);
            assert!(rows.len() <= 105);
        }
        assert_eq!(rows.len(), 105);
    }
    let (_, _, first) = get(&app, "/api/v1/assets?limit=25&eligible=true", &cookie, &csrf).await;
    let cursor = first["next_cursor"].as_str().unwrap();
    for path in [
        format!("/api/v1/services?cursor={cursor}"),
        format!("/api/v1/assets?limit=26&cursor={cursor}"),
        format!("/api/v1/assets?eligible=false&cursor={cursor}"),
    ] {
        let (status, _, body) = get(&app, &path, &cookie, &csrf).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "INVALID_INPUT");
        assert_eq!(body["detail"], "CURSOR_SCOPE_MISMATCH");
    }
    let mut altered = cursor.as_bytes().to_vec();
    altered[10] = if altered[10] == b'A' { b'B' } else { b'A' };
    let (status, _, body) = get(
        &app,
        &format!(
            "/api/v1/assets?cursor={}",
            String::from_utf8(altered).unwrap()
        ),
        &cookie,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
    assert_eq!(body["detail"], "CURSOR_INVALID");
    let (status, _, _) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("Added after snapshot"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, next) = get(&app, &format!("/api/v1/assets?cursor={cursor}"), &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["revision"], first["revision"]);
    assert!(
        next["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["definition"]["name"] != "Added after snapshot")
    );
    assert_eq!(
        get(
            &app,
            &format!("/api/v1/assets?cursor={cursor}"),
            "session=invalid"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn response_byte_cap_returns_a_smaller_page_and_continuation() {
    let store = Store::in_memory().unwrap();
    let at = chrono::Utc::now().timestamp();
    let tenant = store
        .ensure_tenant(ORG, PROJECT, "Local development", at)
        .unwrap();
    store
        .ensure_principal(&tenant, PRINCIPAL, "human", at)
        .unwrap();
    for n in 0..4 {
        store
            .submit_unenrolled_request(
                &tenant,
                PRINCIPAL,
                "access_request",
                &json!({"number":n,"large":"x".repeat(60_000)}),
                &Uuid::new_v4().to_string(),
                at,
            )
            .unwrap();
    }
    let (app, _) = app(store);
    let (cookie, csrf) = login(&app).await;
    let (status, _, first) = get(&app, "/api/v1/access-requests?limit=100", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["data"].as_array().unwrap().len(), 3);
    let cursor = first["next_cursor"].as_str().unwrap();
    let (status, _, next) = get(
        &app,
        &format!("/api/v1/access-requests?cursor={cursor}"),
        &cookie,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["data"].as_array().unwrap().len(), 1);
    assert!(next["next_cursor"].is_null());
}
#[tokio::test]
async fn eligible_target_pages_skip_revoked_and_expired_reports_and_keep_continuation() {
    let store = Store::in_memory().unwrap();
    let at = chrono::Utc::now().timestamp();
    let tenant = store
        .ensure_tenant(ORG, PROJECT, "Local development", at - 301)
        .unwrap();
    store
        .ensure_principal(&tenant, PRINCIPAL, "human", at - 301)
        .unwrap();
    let (stale, _) = enrolled_target::enrolled(&store, &tenant, PRINCIPAL, at - 301);
    let (revoked, _) = enrolled_target::enrolled(&store, &tenant, PRINCIPAL, at);
    store
        .revoke_enrollment(&tenant, PRINCIPAL, &revoked, at)
        .unwrap();
    let (app, target) = app(store);
    let (cookie, csrf) = login(&app).await;
    let (status, _, first) = get(&app, "/api/v1/targets?limit=1&eligible=true", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(first["data"].as_array().unwrap().is_empty());
    assert!(
        first["next_cursor"].is_string(),
        "empty filtered page must retain continuation"
    );
    let mut cursor = first["next_cursor"].as_str().map(str::to_owned);
    let mut rows = vec![];
    let mut pages = 0;
    while let Some(c) = cursor {
        pages += 1;
        assert!(pages <= 3);
        let (status, _, page) = get(&app, &format!("/api/v1/targets?cursor={c}"), &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        rows.extend(page["data"].as_array().unwrap().clone());
        cursor = page["next_cursor"].as_str().map(str::to_owned);
    }
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["target_id"], target);
    assert_eq!(rows[0]["enforcement_backend"], "nftables");
    assert!(rows[0]["observed_at"].is_null());
    let (_, _, all) = get(&app, "/api/v1/targets?limit=100", &cookie, &csrf).await;
    assert_eq!(all["data"].as_array().unwrap().len(), 3);
    for id in [&stale, &revoked] {
        assert_eq!(
            all["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["target_id"] == *id)
                .unwrap()["state"],
            "quarantined"
        );
    }
    let (_, _, created) = post(
        &app,
        "/api/v1/assets",
        &cookie,
        &csrf,
        &Uuid::new_v4().to_string(),
        None,
        asset("Destination"),
    )
    .await;
    let aid = created["data"]["asset_id"].as_str().unwrap();
    for (n, id) in [&stale, &revoked].into_iter().enumerate() {
        let (status, _, _) = post(
            &app,
            "/api/v1/services",
            &cookie,
            &csrf,
            &Uuid::new_v4().to_string(),
            None,
            service(&format!("bad-{n}"), aid, id),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, _, page) = get(&app, "/api/v1/enrollments?limit=1", &cookie, &csrf).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page["next_cursor"].is_string());
}
