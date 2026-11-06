//! Disposable, purpose-separated signed peer for the isolated bootstrap lab.
//! This development fixture is not a production enrollment or probe service.
#[cfg(target_os = "linux")]
mod linux {
    use ed25519_dalek::SigningKey;
    use fw_authority::{
        sign_bootstrap_probe_response, verify_bootstrap_probe_response, BootstrapPeerResponse,
        BootstrapProbeKind, BootstrapProbeRequest,
    };
    use fw_backend_linux::BootstrapManagementBaseline;
    use fw_contracts::parse_strict_with_limit;
    use serde_json::json;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{Duration, Instant};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    const LIMIT: usize = 4096;
    fn bounded(path: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum as u64 {
            return Err("fixture input boundary".into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err("fixture input limit".into());
        }
        Ok(bytes)
    }
    fn key(path: &str) -> Result<SigningKey> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no pointer arguments or side effects.
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() != 32
        {
            return Err("private peer fixture seed".into());
        }
        let mut bytes = [0; 32];
        file.read_exact(&mut bytes)?;
        let key = SigningKey::from_bytes(&bytes);
        bytes.fill(0);
        Ok(key)
    }
    fn baseline(path: &str) -> Result<BootstrapManagementBaseline> {
        let value: BootstrapManagementBaseline =
            parse_strict_with_limit(&bounded(path, 16384)?, 16384)?;
        value.validate()?;
        Ok(value)
    }
    fn request(
        bytes: &[u8],
        expected: Option<BootstrapProbeKind>,
    ) -> Result<BootstrapProbeRequest> {
        if bytes.len() > LIMIT || bytes.last() != Some(&b'\n') {
            return Err("peer fixture framing".into());
        }
        let value: BootstrapProbeRequest =
            parse_strict_with_limit(&bytes[..bytes.len() - 1], LIMIT)?;
        value.canonical_bytes()?;
        if expected.is_some_and(|kind| value.kind != kind)
            || (expected.is_none() && value.kind == BootstrapProbeKind::ManagementTcp)
        {
            return Err("peer fixture endpoint binding".into());
        }
        Ok(value)
    }
    fn tcp(mut stream: TcpStream, key: &SigningKey) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut bytes = Vec::new();
        let mut byte = [0];
        while bytes.len() <= LIMIT {
            stream.set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("peer frame deadline")?,
            ))?;
            if stream.read(&mut byte)? == 0 {
                break;
            }
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        let value = request(&bytes, Some(BootstrapProbeKind::ManagementTcp))?;
        stream.write_all(&sign_bootstrap_probe_response(&value, key)?.wire_bytes()?)?;
        Ok(())
    }
    // Both retained UDP endpoints support role swaps across approved epochs.
    // TCP remains management-only; signed request context binds kind and B.
    fn udp(socket: &UdpSocket, key: &SigningKey) -> Result<bool> {
        let mut bytes = [0; LIMIT + 1];
        match socket.recv_from(&mut bytes) {
            Ok((count, peer)) => {
                if let Ok(value) = request(&bytes[..count], None) {
                    socket.send_to(
                        &sign_bootstrap_probe_response(&value, key)?.wire_bytes()?,
                        peer,
                    )?;
                }
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn serve(baseline_path: &str, seed_path: &str, ready_path: &str) -> Result<()> {
        // SAFETY: geteuid has no pointer arguments or side effects.
        if unsafe { libc::geteuid() } == 0 {
            return Err("peer fixture requires a distinct ordinary UID".into());
        }
        let b = baseline(baseline_path)?;
        let key = key(seed_path)?;
        if key.verifying_key().to_bytes() != b.peer_probe_public_key {
            return Err("approved peer key mismatch".into());
        }
        if fs::read_link("/proc/self/ns/net")?.to_string_lossy() == b.network_namespace {
            return Err("peer must be outside target namespace".into());
        }
        let tcp_socket = TcpListener::bind((b.peer_address.as_str(), b.management_tcp_port))?;
        let positive = UdpSocket::bind((b.peer_address.as_str(), b.positive_udp_port))?;
        let negative = UdpSocket::bind((b.peer_address.as_str(), b.negative_udp_port))?;
        tcp_socket.set_nonblocking(true)?;
        positive.set_nonblocking(true)?;
        negative.set_nonblocking(true)?;
        let mut ready = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(ready_path)?;
        ready.write_all(b"fw-bootstrap-peer-ready-v1\n")?;
        ready.sync_all()?;
        let end = Instant::now() + Duration::from_secs(300);
        let mut handled = 0;
        while Instant::now() < end && handled < 128 {
            match tcp_socket.accept() {
                Ok((stream, _)) => {
                    let _ = tcp(stream, &key);
                    handled += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            handled += usize::from(udp(&positive, &key)?);
            handled += usize::from(udp(&negative, &key)?);
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
    fn run() -> Result<()> {
        if fs::read("/lab/DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE")?
            != b"fw-isolated-target-bootstrap-v1\n"
        {
            return Err("disposable namespace marker required".into());
        }
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        match args.as_slice() {
            [operation, seed] if operation == "public-key" => println!(
                "{}",
                json!({"public_key":key(seed)?.verifying_key().to_bytes().to_vec()})
            ),
            [operation, b, seed, ready] if operation == "serve" => serve(b, seed, ready)?,
            [operation, b, req, response] if operation == "verify" => {
                let request: BootstrapProbeRequest =
                    parse_strict_with_limit(&bounded(req, LIMIT)?, LIMIT)?;
                let response: BootstrapPeerResponse =
                    parse_strict_with_limit(&bounded(response, LIMIT)?, LIMIT)?;
                verify_bootstrap_probe_response(&request, &response, &baseline(b)?)?;
                println!(
                    "{}",
                    json!({"verified":true,"request_hash":request.hash()?})
                );
            }
            _ => return Err("explicit peer fixture operation required".into()),
        }
        Ok(())
    }
    pub(super) fn main() {
        if run().is_err() {
            eprintln!("TARGET_BOOTSTRAP_PEER_FIXTURE_REJECTED");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("TARGET_BOOTSTRAP_PEER_FIXTURE_UNSUPPORTED_PLATFORM");
    std::process::exit(2);
}
