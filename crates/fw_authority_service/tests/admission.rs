//! Exercise the shipped executable, including its TCP accept/header boundary.
#[path = "support/authenticator.rs"]
mod authenticator;
#[path = "support/plans.rs"]
mod plans;
#[path = "../../fw_authority/tests/support/private_directory.rs"]
mod private_directory;
use authenticator::{Authenticator, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant};
use fw_webauthn::WebAuthn;
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
static SERVERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

fn write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

struct Server {
    _server_slot: tokio::sync::SemaphorePermit<'static>,
    _directory: tempfile::TempDir,
    child: Child,
    address: std::net::SocketAddr,
    origin: String,
    key: Authenticator,
    db: std::path::PathBuf,
    credential: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct Reply {
    status: u16,
    body: Value,
    cookie: Option<String>,
}
impl Server {
    async fn start() -> Self {
        // Keep the sub-second admission deadline meaningful on small CI hosts.
        let server_slot = SERVERS.acquire().await.unwrap();
        let directory = private_directory::private_directory();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", address.port());
        let db = directory.path().join("authority.sqlite3");
        let now = chrono::Utc::now().timestamp();
        let mut store = AuthorityStore::open(&db).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        // Registration clientData is created by the fixture at its original
        // localhost origin. Only the pinned key is reused at the configured RP.
        let original = WebAuthn::new(authenticator::ORIGIN).unwrap();
        let original_ceremony = original
            .begin_registration(PRINCIPAL, "TCP admission key", &[])
            .unwrap();
        let credential = original
            .finish_registration(
                &original_ceremony.state,
                &key.registration(&original_ceremony.options),
            )
            .unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        store
            .provision_principal(&tenant, PRINCIPAL, "local-test-oob", "owner", now)
            .unwrap();
        store
            .pin_credential(&tenant, &credential, now, now + 7200, now)
            .unwrap();
        store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                now,
                now + 7200,
                now,
            )
            .unwrap();
        let (plan, requirements, _) = plans::complete_plan(now);
        store
            .register_plan(&tenant, &plan, &requirements, now)
            .unwrap();
        drop(store);
        let ui = private_directory::private_directory();
        write(
            &ui.path().join("index.html"),
            b"<!doctype html><title>Authority</title>",
        );
        let config = json!({"origin":origin,"controller_origin":"http://localhost:8799","database":db,"ui_directory":ui.path(),"profiles":{"owner":{"org_id":ORG,"project_id":PROJECT,"principal_id":PRINCIPAL,"credential_id":credential.id()}},"review_evidence":{}});
        let config_path = directory.path().join("config.json");
        let key_path = directory.path().join("session.key");
        write(&config_path, &serde_json::to_vec(&config).unwrap());
        write(&key_path, &[7; 32]);
        drop(listener);
        let child = Command::new(env!("CARGO_BIN_EXE_fw_authority_service"))
            .env("TOKIO_WORKER_THREADS", "2")
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--session-key-file",
                key_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Self {
            _server_slot: server_slot,
            _directory: directory,
            child,
            address,
            origin,
            key,
            db,
            credential: credential.id(),
        };
        for _ in 0..100 {
            if let Ok(Ok(reply)) = tokio::time::timeout(
                Duration::from_millis(100),
                server.request("GET", "/authority/v1/session", None, None, None),
            )
            .await
                && reply.status == 200
            {
                return server;
            }
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "authority executable exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("authority executable readiness deadline");
    }
    fn headers(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        length: usize,
    ) -> String {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nOrigin: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n",
            self.address.port(),
            self.origin
        );
        if let Some(cookie) = cookie {
            head.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        if let Some(csrf) = csrf {
            head.push_str(&format!("X-Authority-CSRF: {csrf}\r\n"));
        }
        head.push_str("\r\n");
        head
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: Option<Value>,
    ) -> std::io::Result<Reply> {
        let body = body.map(|v| v.to_string()).unwrap_or_default();
        let mut stream = TcpStream::connect(self.address).await?;
        stream
            .write_all(
                self.headers(method, path, cookie, csrf, body.len())
                    .as_bytes(),
            )
            .await?;
        stream.write_all(body.as_bytes()).await?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        let raw = String::from_utf8(bytes).map_err(std::io::Error::other)?;
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .ok_or_else(|| std::io::Error::other("connection closed without response"))?;
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        let cookie = head.lines().find_map(|line| {
            line.strip_prefix("set-cookie: ")
                .map(|v| v.split(';').next().unwrap().to_owned())
        });
        Ok(Reply {
            status,
            body: serde_json::from_str(body).map_err(std::io::Error::other)?,
            cookie,
        })
    }
    async fn login(&self, counter: u32) -> (String, String) {
        let boot = self
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap();
        let cookie = boot.cookie.unwrap();
        let csrf = boot.body["csrf_token"].as_str().unwrap();
        let begin = self
            .request(
                "POST",
                "/authority/v1/auth/options",
                Some(&cookie),
                Some(csrf),
                Some(json!({"profile":"owner"})),
            )
            .await
            .unwrap();
        assert_eq!(begin.status, 200);
        let assertion = self
            .key
            .assertion(&begin.body["options"], counter, 0x05, &self.origin);
        let done = self
            .request(
                "POST",
                "/authority/v1/auth/verify",
                Some(&cookie),
                Some(csrf),
                Some(json!({"ceremony_id":begin.body["ceremony_id"],"assertion":assertion})),
            )
            .await
            .unwrap();
        assert_eq!(done.status, 200);
        assert_eq!(done.body["authenticated"], true);
        (
            done.cookie.unwrap(),
            done.body["csrf_token"].as_str().unwrap().to_owned(),
        )
    }
    async fn idle(&self, count: usize) -> Vec<TcpStream> {
        let mut sockets = Vec::new();
        for _ in 0..count {
            sockets.push(TcpStream::connect(self.address).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        sockets
    }
    async fn slow_bodies(&self, count: usize) -> Vec<TcpStream> {
        let mut sockets = Vec::new();
        for _ in 0..count {
            let mut stream = TcpStream::connect(self.address).await.unwrap();
            stream
                .write_all(
                    self.headers("POST", "/authority/v1/auth/options", None, None, 4096)
                        .as_bytes(),
                )
                .await
                .unwrap();
            sockets.push(stream);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        sockets
    }
}

#[tokio::test]
async fn authenticated_request_survives_64_idle_anonymous_connections() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    let _idle = server.idle(64).await;
    let reply = tokio::time::timeout(
        Duration::from_millis(800),
        server.request(
            "GET",
            "/authority/v1/plans",
            Some(&cookie),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert!(
        matches!(reply, Ok(Ok(Reply { status: 200, .. }))),
        "64 idle unauthenticated sockets starved a verified request"
    );
}

#[tokio::test]
async fn public_slow_bodies_cannot_take_authenticated_work_capacity() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    let _sockets = server.slow_bodies(64).await;
    let reply = tokio::time::timeout(
        Duration::from_millis(800),
        server.request(
            "GET",
            "/authority/v1/plans",
            Some(&cookie),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert!(
        matches!(reply, Ok(Ok(Reply { status: 200, .. }))),
        "public slow bodies exhausted authenticated work"
    );
}

#[tokio::test]
async fn fresh_real_passkey_login_survives_64_idle_connections() {
    let server = Server::start().await;
    let _idle = server.idle(64).await;
    let (cookie, csrf) = tokio::time::timeout(Duration::from_millis(800), server.login(1))
        .await
        .unwrap();
    assert_eq!(
        server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None
            )
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn forged_cookie_or_missing_memory_proof_never_uses_reserved_work() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    let _sockets = server.slow_bodies(8).await;
    for (cookie, csrf) in [
        (None, Some(csrf.as_str())),
        (Some(cookie.as_str()), None),
        (Some(cookie.as_str()), Some("forged-proof")),
        (Some("__Host-fw_authority=forged"), Some(csrf.as_str())),
    ] {
        let reply = server
            .request("GET", "/authority/v1/plans", cookie, csrf, None)
            .await
            .unwrap();
        assert_eq!(
            reply.status, 429,
            "unverified headers borrowed reserved authenticated work"
        );
    }
    assert_eq!(
        server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None
            )
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn revoked_missing_or_revision_stale_cached_sessions_do_not_get_reserved_work() {
    for change in ["revoke", "missing", "revision"] {
        let server = Server::start().await;
        let (cookie, csrf) = server.login(1).await;
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        match change {
            "revoke"=>AuthorityStore::open(&server.db).unwrap().revoke_credential(&tenant,&server.credential,chrono::Utc::now().timestamp()).unwrap(),
            "revision"=>AuthorityStore::open(&server.db).unwrap().grant_role(&tenant,PRINCIPAL,ApprovalRole::NetworkReviewer,chrono::Utc::now().timestamp(),chrono::Utc::now().timestamp()+7200,chrono::Utc::now().timestamp()).map(|_|()).unwrap(),
            "missing"=>rusqlite::Connection::open(&server.db).unwrap().execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER authority_credentials_no_delete; DELETE FROM authority_credentials;").unwrap(),
            _=>unreachable!(),
        }
        let _sockets = server.slow_bodies(8).await;
        let reply = server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            reply.status, 429,
            "{change} cache entry borrowed reserved work before current validation"
        );
    }
}

#[tokio::test]
async fn logout_removes_reserved_eligibility_before_responding() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    assert_eq!(
        server
            .request(
                "POST",
                "/authority/v1/logout",
                Some(&cookie),
                Some(&csrf),
                Some(json!({}))
            )
            .await
            .unwrap()
            .status,
        200
    );
    let _sockets = server.slow_bodies(8).await;
    assert_eq!(
        server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None
            )
            .await
            .unwrap()
            .status,
        429
    );
}

#[tokio::test]
async fn disconnected_partial_bodies_release_public_capacity() {
    let server = Server::start().await;
    let sockets = server.slow_bodies(8).await;
    assert_eq!(
        server
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap()
            .status,
        429
    );
    drop(sockets);
    for _ in 0..20 {
        if server
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap()
            .status
            == 200
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("disconnected body readers retained public permits");
}

#[tokio::test]
async fn disconnected_blocking_login_jobs_retain_permits_until_database_completion() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    let boot = server
        .request("GET", "/authority/v1/session", None, None, None)
        .await
        .unwrap();
    let anonymous = boot.cookie.unwrap();
    let proof = boot.body["csrf_token"].as_str().unwrap();
    let begin = server
        .request(
            "POST",
            "/authority/v1/auth/options",
            Some(&anonymous),
            Some(proof),
            Some(json!({"profile":"owner"})),
        )
        .await
        .unwrap();
    assert_eq!(begin.status, 200);
    let body=json!({"ceremony_id":begin.body["ceremony_id"],"assertion":server.key.assertion(&begin.body["options"],2,0x05,&server.origin)}).to_string();
    let database = rusqlite::Connection::open(&server.db).unwrap();
    database.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut sockets = Vec::new();
    for _ in 0..8 {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        stream
            .write_all(
                server
                    .headers(
                        "POST",
                        "/authority/v1/auth/verify",
                        Some(&anonymous),
                        Some(proof),
                        body.len(),
                    )
                    .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body.as_bytes()).await.unwrap();
        sockets.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(sockets);
    assert_eq!(
        server
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap()
            .status,
        429,
        "disconnect released still-running blocking work permits"
    );
    database.execute_batch("COMMIT").unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if server
                .request("GET", "/authority/v1/session", None, None, None)
                .await
                .unwrap()
                .status
                == 200
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(recovered.is_ok());
    assert_eq!(
        server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None
            )
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn slow_header_and_body_progress_do_not_extend_deadlines_and_public_work_recovers() {
    let server = Server::start().await;
    let (cookie, csrf) = server.login(1).await;
    let mut header = TcpStream::connect(server.address).await.unwrap();
    let started = std::time::Instant::now();
    for byte in b"GET" {
        header.write_all(&[*byte]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), header.read_to_end(&mut received))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(1600));
    let mut bodies = server.slow_bodies(8).await;
    assert_eq!(
        server
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap()
            .status,
        429
    );
    assert_eq!(
        server
            .request(
                "GET",
                "/authority/v1/plans",
                Some(&cookie),
                Some(&csrf),
                None
            )
            .await
            .unwrap()
            .status,
        200
    );
    for _ in 0..10 {
        let _ = bodies[0].write_all(b" ").await;
        tokio::time::sleep(Duration::from_millis(330)).await;
    }
    assert_eq!(
        server
            .request("GET", "/authority/v1/session", None, None, None)
            .await
            .unwrap()
            .status,
        200
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), server.login(2))
        .await
        .unwrap();
}
