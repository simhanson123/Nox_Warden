use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use fw_control::{AppState, enrollment_router, router, tls::EnrollmentListener};
use fw_enrollment::{ControllerPki, DeviceIdentity, EnrollmentRequest, EnrollmentResponse};
use fw_store::Store;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "http://127.0.0.1:8787";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fw-enrollment-http-{}", Uuid::new_v4())))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Running {
    app: axum::Router,
    ca_pem: String,
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    _scratch: Scratch,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Running {
    async fn new() -> Self {
        let scratch = Scratch::new();
        let pki =
            fw_enrollment::init_controller_pki(&scratch.0, chrono::Utc::now().timestamp()).unwrap();
        let ca_pem = pki.authority.ca_certificate_pem().into();
        let listener = EnrollmentListener::bind("127.0.0.1:0".parse().unwrap(), &pki)
            .await
            .unwrap();
        let address = listener.local_socket_addr().unwrap();
        let state = Arc::new(
            AppState::new(Store::in_memory().unwrap(), ORIGIN.into(), "bootstrap-test")
                .unwrap()
                .with_enrollment(pki.authority),
        );
        let app = router(state.clone(), "/tmp/fw-web-not-present".into());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                enrollment_router(state)
                    .into_make_service_with_connect_info::<fw_control::tls::TlsPeer>(),
            )
            .await
            .unwrap();
        });
        Self {
            app,
            ca_pem,
            address,
            server,
            _scratch: scratch,
        }
    }
}
async fn public(
    app: &axum::Router,
    path: &str,
    method: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    key: &str,
    body: Value,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", ORIGIN)
        .header("idempotency-key", key)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|value| value.to_str().unwrap().split(';').next().unwrap().into());
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 262_144).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookie,
    )
}
async fn login(app: &axum::Router) -> (String, String) {
    let (status, value, cookie) = public(
        app,
        "/api/v1/session/bootstrap",
        "POST",
        None,
        None,
        &Uuid::new_v4().to_string(),
        json!({"token":"bootstrap-test"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (
        cookie.unwrap(),
        value["data"]["csrf_token"].as_str().unwrap().into(),
    )
}
async fn invite(
    run: &Running,
    cookie: &str,
    csrf: &str,
    device: &DeviceIdentity,
) -> (Value, EnrollmentRequest) {
    let token = fw_enrollment::random_token().unwrap();
    let input = json!({"name":"Test device", "platform":"linux", "expected_key_fingerprint":device.key_fingerprint,"token_hash":fw_enrollment::hash_bytes(token.as_bytes())});
    let (status, result, _) = public(
        &run.app,
        "/api/v1/enrollment-tokens",
        "POST",
        Some(cookie),
        Some(csrf),
        &Uuid::new_v4().to_string(),
        input,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let request = EnrollmentRequest {
        schema_version: "f.enrollment-request/v1".into(),
        request_id: Uuid::new_v4().to_string(),
        token,
        csr_pem: device.csr_pem.clone(),
        expected_key_fingerprint: device.key_fingerprint.clone(),
        nonce: fw_enrollment::random_token().unwrap(),
        platform: "linux".into(),
        agent_version: "0.1.0-test".into(),
    };
    (result["data"].clone(), request)
}

fn tls_config(ca: &str, identity: Option<(&str, &str)>) -> rustls::ClientConfig {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots);
    match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(chain.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
            )
            .unwrap(),
    }
}
async fn tls_request(
    run: &Running,
    path: &str,
    method: &str,
    body: &str,
    identity: Option<(&str, &str)>,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    tls_request_headers(run, path, method, body, identity, "").await
}
async fn tls_request_headers(
    run: &Running,
    path: &str,
    method: &str,
    body: &str,
    identity: Option<(&str, &str)>,
    headers: &str,
) -> Result<(u16, Value), Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(run.address).await?;
    let connector = TlsConnector::from(Arc::new(tls_config(&run.ca_pem, identity)));
    let mut stream = connector
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() < 262_144);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end])?;
            let length = headers.lines().find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|length| length.parse::<usize>().unwrap())
            });
            if length.is_some_and(|length| bytes.len() >= end + 4 + length) {
                break;
            }
        }
    }
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("missing response headers")?;
    let status: u16 = std::str::from_utf8(&bytes[..end])?
        .split_whitespace()
        .nth(1)
        .ok_or("missing status")?
        .parse()?;
    let body = serde_json::from_slice(&bytes[end + 4..])?;
    Ok((status, body))
}
fn capability(target_id: &str) -> Value {
    let now = chrono::Utc::now();
    let names = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ];
    let features: serde_json::Map<String,Value> = names.into_iter().map(|name| (name.into(),json!({"state":"unverified","reason_code":"QUALIFICATION_REQUIRED","evidence_hash":null}))).collect();
    json!({"schema_version":"f.target-capability/v1","target_id":target_id,"platform":"linux","enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":"test-kernel","backend_version":"unavailable","executor_build_hash":fw_enrollment::hash_bytes(b"test-only-doctor-fixture"),"checked_at":now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"valid_until":(now+chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ").to_string(),"profiles":[],"families":[],"directions":[],"protocols":[],"binding_kinds":[],"features":features,"max_policies":4096,"max_rules":100000,"max_artifact_bytes":16777216,"qualification_profiles":[],"interfaces":[]})
}

#[tokio::test]
async fn token_creation_requires_session_csrf_and_replays_without_plaintext_secret() {
    let run = Running::new().await;
    let (cookie, csrf) = login(&run.app).await;
    let input = json!({"name":"Device","platform":"linux","expected_key_fingerprint":fw_enrollment::hash_bytes(b"key"),"token_hash":fw_enrollment::hash_bytes(b"synthetic-test-secret")});
    let key = Uuid::new_v4().to_string();
    for (cookie, csrf, expected) in [
        (None, None, StatusCode::UNAUTHORIZED),
        (Some(cookie.as_str()), Some("bad"), StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            public(
                &run.app,
                "/api/v1/enrollment-tokens",
                "POST",
                cookie,
                csrf,
                &key,
                input.clone()
            )
            .await
            .0,
            expected
        );
    }
    let first = public(
        &run.app,
        "/api/v1/enrollment-tokens",
        "POST",
        Some(&cookie),
        Some(&csrf),
        &key,
        input.clone(),
    )
    .await;
    let second = public(
        &run.app,
        "/api/v1/enrollment-tokens",
        "POST",
        Some(&cookie),
        Some(&csrf),
        &key,
        input.clone(),
    )
    .await;
    assert_eq!(first.0, StatusCode::CREATED);
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(first.1["data"], second.1["data"]);
    assert!(!first.1.to_string().contains("synthetic-test-secret"));
    assert!(first.1["data"].get("token").is_none());
    let mut changed = input;
    changed["name"] = json!("different");
    assert_eq!(
        public(
            &run.app,
            "/api/v1/enrollment-tokens",
            "POST",
            Some(&cookie),
            Some(&csrf),
            &key,
            changed
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn real_tls_enrollment_capability_and_revocation_remain_observe_only() {
    let run = Running::new().await;
    let (cookie, csrf) = login(&run.app).await;
    let device = fw_enrollment::generate_device_identity().unwrap();
    let (invitation, request) = invite(&run, &cookie, &csrf, &device).await;
    let target_id = invitation["target_id"].as_str().unwrap();
    let request_bytes = serde_json::to_string(&request).unwrap();
    let (status, first) = tls_request(&run, "/internal/v1/enroll", "POST", &request_bytes, None)
        .await
        .unwrap();
    assert_eq!(status, 200, "{first}");
    let response: EnrollmentResponse = serde_json::from_value(first.clone()).unwrap();
    fw_enrollment::verify_enrollment_response(
        &response,
        &device,
        &run.ca_pem,
        target_id,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert_eq!(response.mode, "observe");
    assert_eq!(response.authority_epoch, "0");
    let (_, replay) = tls_request(&run, "/internal/v1/enroll", "POST", &request_bytes, None)
        .await
        .unwrap();
    assert_eq!(first, replay);
    let (_, targets, _) = public(
        &run.app,
        "/api/v1/targets",
        "GET",
        Some(&cookie),
        None,
        &Uuid::new_v4().to_string(),
        json!({}),
    )
    .await;
    assert_eq!(targets["data"], json!([])); // No fabricated capability before the actual report.
    let report = capability(target_id);
    assert_eq!(
        tls_request(
            &run,
            "/internal/v1/capabilities",
            "POST",
            &report.to_string(),
            None
        )
        .await
        .unwrap()
        .0,
        401
    );
    let identity = Some((
        response.certificate_chain_pem.as_str(),
        device.private_key_pem.as_str(),
    ));
    let (status, saved) = tls_request(
        &run,
        "/internal/v1/capabilities",
        "POST",
        &report.to_string(),
        identity,
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["actions"], json!([]));
    assert_eq!(saved["data"]["state"], "observe_only");
    assert_eq!(
        saved["data"]["capability_hash"],
        fw_contracts::canonical_hash(&report).unwrap()
    );
    let (_, listed, _) = public(
        &run.app,
        "/api/v1/targets",
        "GET",
        Some(&cookie),
        None,
        &Uuid::new_v4().to_string(),
        json!({}),
    )
    .await;
    assert_eq!(listed["data"][0]["target_id"], target_id);
    let mut wrong_target = report.clone();
    wrong_target["target_id"] = json!(Uuid::new_v4());
    assert_eq!(
        tls_request(
            &run,
            "/internal/v1/capabilities",
            "POST",
            &wrong_target.to_string(),
            identity
        )
        .await
        .unwrap()
        .0,
        400
    );
    let mut forged = report;
    forged["features"]["atomic_apply"] = json!({"state":"supported","reason_code":null,"evidence_hash":fw_enrollment::hash_bytes(b"untrusted-claim")});
    assert_eq!(
        tls_request(
            &run,
            "/internal/v1/capabilities",
            "POST",
            &forged.to_string(),
            identity
        )
        .await
        .unwrap()
        .0,
        400
    );
    let (status, _) = tls_request(&run, "/internal/v1/device-status", "GET", "", identity)
        .await
        .unwrap();
    assert_eq!(status, 200);
    let (_, status, _) = public(
        &run.app,
        "/api/v1/status",
        "GET",
        Some(&cookie),
        None,
        &Uuid::new_v4().to_string(),
        json!({}),
    )
    .await;
    assert_eq!(status["data"]["enforcement"], false);
    let (status, revoked, _) = public(
        &run.app,
        &format!("/api/v1/enrollments/{target_id}/revoke"),
        "POST",
        Some(&cookie),
        Some(&csrf),
        &Uuid::new_v4().to_string(),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(
        tls_request(&run, "/internal/v1/device-status", "GET", "", identity)
            .await
            .unwrap()
            .0,
        403
    );
    assert_eq!(
        tls_request(&run, "/internal/v1/enroll", "POST", &request_bytes, None)
            .await
            .unwrap()
            .0,
        403
    );
}

#[tokio::test]
async fn identity_headers_cannot_replace_a_verified_client_certificate() {
    let run = Running::new().await;
    let (status, value) = tls_request_headers(&run, "/internal/v1/device-status", "GET", "", None,
        "X-Client-Cert: attacker-supplied\r\nX-Target-Id: 00000000-0000-4000-8000-000000000099\r\nX-Forwarded-Client-Cert: verified\r\n").await.unwrap();
    assert_eq!(status, 401);
    assert_eq!(value["detail"], "CLIENT_CERTIFICATE_REQUIRED");
}

#[tokio::test]
async fn an_incomplete_handshake_does_not_block_a_legitimate_client() {
    let run = Running::new().await;
    // This client holds a TCP socket without sending a TLS ClientHello.
    let stalled = TcpStream::connect(run.address).await.unwrap();
    tokio::task::yield_now().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tls_request(&run, "/internal/v1/device-status", "GET", "", None),
    )
    .await
    .expect("the valid TLS handshake must not wait for the stalled client's five-second deadline")
    .unwrap();
    assert_eq!(response.0, 401);
    drop(stalled);
}

#[tokio::test]
async fn token_issuance_is_disabled_without_configured_enrollment_tls() {
    let app = router(
        Arc::new(
            AppState::new(Store::in_memory().unwrap(), ORIGIN.into(), "bootstrap-test").unwrap(),
        ),
        "/tmp/fw-web-not-present".into(),
    );
    let (cookie, csrf) = login(&app).await;
    let input = json!({"name":"Device","platform":"linux","expected_key_fingerprint":fw_enrollment::hash_bytes(b"key"),"token_hash":fw_enrollment::hash_bytes(b"test-token")});
    let (status, value, _) = public(
        &app,
        "/api/v1/enrollment-tokens",
        "POST",
        Some(&cookie),
        Some(&csrf),
        &Uuid::new_v4().to_string(),
        input,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["detail"], "ENROLLMENT_DISABLED");
}

#[tokio::test]
async fn different_csr_cannot_consume_reserved_token_and_internal_routes_are_not_public() {
    let run = Running::new().await;
    let (cookie, csrf) = login(&run.app).await;
    let device = fw_enrollment::generate_device_identity().unwrap();
    let (_, mut request) = invite(&run, &cookie, &csrf, &device).await;
    let (status, _, _) = public(
        &run.app,
        "/internal/v1/enroll",
        "POST",
        None,
        None,
        &Uuid::new_v4().to_string(),
        serde_json::to_value(&request).unwrap(),
    )
    .await;
    assert!(matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ));
    let stranger = fw_enrollment::generate_device_identity().unwrap();
    request.csr_pem = stranger.csr_pem;
    request.expected_key_fingerprint = stranger.key_fingerprint;
    let (status, _) = tls_request(
        &run,
        "/internal/v1/enroll",
        "POST",
        &serde_json::to_string(&request).unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_ne!(status, 200);
    request.csr_pem = device.csr_pem;
    request.expected_key_fingerprint = device.key_fingerprint;
    assert_eq!(
        tls_request(
            &run,
            "/internal/v1/enroll",
            "POST",
            &serde_json::to_string(&request).unwrap(),
            None
        )
        .await
        .unwrap()
        .0,
        200
    );
}

#[tokio::test]
async fn untrusted_server_and_client_certificates_are_rejected_by_tls() {
    let run = Running::new().await;
    let other = Scratch::new();
    let other_pki: ControllerPki =
        fw_enrollment::init_controller_pki(&other.0, chrono::Utc::now().timestamp()).unwrap();
    let tcp = TcpStream::connect(run.address).await.unwrap();
    let connector = TlsConnector::from(Arc::new(tls_config(
        other_pki.authority.ca_certificate_pem(),
        None,
    )));
    assert!(
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .is_err()
    );
    let identity = fw_enrollment::generate_device_identity().unwrap();
    let request = EnrollmentRequest {
        schema_version: "f.enrollment-request/v1".into(),
        request_id: Uuid::new_v4().to_string(),
        token: fw_enrollment::random_token().unwrap(),
        csr_pem: identity.csr_pem.clone(),
        expected_key_fingerprint: identity.key_fingerprint.clone(),
        nonce: fw_enrollment::random_token().unwrap(),
        platform: "linux".into(),
        agent_version: "test".into(),
    };
    let csr = fw_enrollment::validate_request(&request).unwrap();
    let response = other_pki
        .authority
        .issue(
            &csr,
            &fw_enrollment::Issuance {
                request_id: request.request_id,
                org_id: fw_control::ORG.into(),
                project_id: fw_control::PROJECT.into(),
                target_id: Uuid::new_v4().to_string(),
                job_id: Uuid::new_v4().to_string(),
                issued_at: chrono::Utc::now().timestamp(),
                authority_epoch: 0,
            },
        )
        .unwrap();
    assert!(
        tls_request(
            &run,
            "/internal/v1/device-status",
            "GET",
            "",
            Some((&response.certificate_chain_pem, &identity.private_key_pem))
        )
        .await
        .is_err()
    );
}
