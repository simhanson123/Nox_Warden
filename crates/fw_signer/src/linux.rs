use crate::{
    Config, Failure, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Result, parse_request,
};
use ed25519_dalek::SigningKey;
use fw_authority::{AuthorityStore, AuthorityTenant};
use fw_webauthn::WebAuthn;
use serde_json::json;
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn identity() -> Result<u32> {
    // SAFETY: these calls have no pointer arguments and only inspect this process.
    let (uid, euid, gid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if uid == 0 || uid != euid || gid != egid {
        return Err(Failure::Identity);
    }
    Ok(uid)
}

fn harden() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid immutable limit pointer; prctl options use scalar arguments.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(Failure::Identity);
    }
    // No concurrent threads exist at startup. Created SQLite sidecars and the
    // initial socket must start private even under a permissive inherited umask.
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}

fn name(value: &std::ffi::OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Failure::Config)
}

/// Walk every directory using descriptors and O_NOFOLLOW. A root-owned sticky
/// temporary directory may be an ancestor; the final parent must belong to the
/// signer and cannot be writable by the controller or any other account.
fn parent(path: &Path, uid: u32) -> Result<(File, CString)> {
    if !path.is_absolute() {
        return Err(Failure::Config);
    }
    let components: Vec<_> = path.components().collect();
    let Some(Component::Normal(leaf)) = components.last() else {
        return Err(Failure::Config);
    };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| Failure::Config)?;
    let root = directory.metadata().map_err(|_| Failure::Config)?;
    if ![0, uid].contains(&root.uid()) || root.mode() & 0o022 != 0 {
        return Err(Failure::Config);
    }
    for component in &components[1..components.len() - 1] {
        let Component::Normal(component) = component else {
            return Err(Failure::Config);
        };
        let component = name(component)?;
        // SAFETY: directory is a live directory descriptor, component is NUL terminated.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Failure::Config);
        }
        // SAFETY: successful openat returned a newly owned descriptor.
        directory = unsafe { File::from_raw_fd(fd) };
        let meta = directory.metadata().map_err(|_| Failure::Config)?;
        let sticky_root = meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0;
        if !meta.is_dir()
            || ![0, uid].contains(&meta.uid())
            || (meta.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(Failure::Config);
        }
    }
    let meta = directory.metadata().map_err(|_| Failure::Config)?;
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(Failure::Config);
    }
    Ok((directory, name(leaf)?))
}

fn private_file(path: &Path, uid: u32, max: usize) -> Result<File> {
    let (directory, leaf) = parent(path, uid)?;
    private_leaf(&directory, &leaf, uid, max)
}
fn private_leaf(directory: &File, leaf: &CString, uid: u32, max: usize) -> Result<File> {
    // O_NONBLOCK avoids waiting on a malicious FIFO before fstat rejects it.
    // SAFETY: valid directory descriptor and NUL terminated leaf.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Failure::Config);
    }
    // SAFETY: successful openat returned a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| Failure::Config)?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.len() > max as u64
    {
        return Err(Failure::Config);
    }
    Ok(file)
}

type DatabaseIdentity = (libc::dev_t, libc::ino_t);

/// SQLite's POSIX locks belong to the process, not one descriptor. Opening and
/// then closing any DB/WAL/SHM descriptor here would release SQLite's locks on
/// that inode. Inspect the leaf without opening it, including before store open.
fn metadata_leaf(
    directory: &File,
    leaf: &CString,
    uid: u32,
    maximum: usize,
) -> Result<Option<DatabaseIdentity>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    loop {
        // SAFETY: directory is live, leaf is NUL terminated, and fstatat writes
        // a complete stat on success. NOFOLLOW rejects symlinks by their type.
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(Failure::Config)
        };
    }
    // SAFETY: successful fstatat initialized all stat fields above.
    let metadata = unsafe { metadata.assume_init() };
    let size = u64::try_from(metadata.st_size).map_err(|_| Failure::Config)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != uid
        || metadata.st_nlink != 1
        || metadata.st_mode & libc::S_IRUSR == 0
        || metadata.st_mode & 0o077 != 0
        || size > maximum as u64
    {
        return Err(Failure::Config);
    }
    Ok(Some((metadata.st_dev, metadata.st_ino)))
}

fn database_at(
    directory: &File,
    leaf: &CString,
    uid: u32,
    input_identities: &[DatabaseIdentity],
) -> Result<DatabaseIdentity> {
    let inspect = |leaf: &CString| {
        let identity = metadata_leaf(directory, leaf, uid, 512 * 1024 * 1024)
            .map_err(|_| Failure::Database)?;
        if identity.is_some_and(|identity| input_identities.contains(&identity)) {
            return Err(Failure::Database);
        }
        Ok(identity)
    };
    let identity = inspect(leaf)?.ok_or(Failure::Database)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = leaf.as_bytes().to_vec();
        sidecar.extend_from_slice(suffix.as_bytes());
        let sidecar = CString::new(sidecar).map_err(|_| Failure::Database)?;
        // Absent sidecars are valid before SQLite creates them. Every other
        // error and every unsafe present leaf fails closed in metadata_leaf.
        inspect(&sidecar)?;
    }
    if inspect(leaf)? != Some(identity) {
        return Err(Failure::Database);
    }
    Ok(identity)
}

fn check_database(
    config: &Config,
    input_identities: &[DatabaseIdentity],
) -> Result<DatabaseIdentity> {
    let (directory, leaf) = parent(Path::new(&config.database_path), config.signer_uid)
        .map_err(|_| Failure::Database)?;
    database_at(&directory, &leaf, config.signer_uid, input_identities)
}

/// Opened only before SQLite. Later checks never open a replacement path, which
/// might now alias a SQLite inode even when its permissions would be rejected.
struct PrivateInput {
    file: File,
    identity: DatabaseIdentity,
    maximum: usize,
}
impl PrivateInput {
    fn open(path: &Path, uid: u32, maximum: usize) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let file = private_file(path, uid, maximum)?;
        let metadata = file.metadata().map_err(|_| Failure::Config)?;
        let input = Self {
            file,
            identity: (metadata.dev(), metadata.ino()),
            maximum,
        };
        let bytes = input.read(path, uid)?;
        Ok((input, bytes))
    }

    fn read(&self, path: &Path, uid: u32) -> Result<Zeroizing<Vec<u8>>> {
        let (directory, leaf) = parent(path, uid)?;
        self.read_at(&directory, &leaf, uid)
    }

    fn read_at(&self, directory: &File, leaf: &CString, uid: u32) -> Result<Zeroizing<Vec<u8>>> {
        let inspect = || metadata_leaf(directory, leaf, uid, self.maximum);
        if inspect()? != Some(self.identity) {
            return Err(Failure::Config);
        }
        let mut bytes = Zeroizing::new(vec![0; self.maximum + 1]);
        let mut offset = 0;
        loop {
            match self.file.read_at(&mut bytes[offset..], offset as u64) {
                Ok(0) => break,
                Ok(count) => {
                    offset += count;
                    if offset > self.maximum {
                        return Err(Failure::Config);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Failure::Config),
            }
        }
        // No replacement leaf is opened, even on refusal. Recheck after the
        // bounded read so a rename, unlink or protection change cannot pass.
        if inspect()? != Some(self.identity) {
            return Err(Failure::Config);
        }
        bytes.truncate(offset);
        Ok(bytes)
    }
}

fn peer(stream: &UnixStream, allowed_uid: u32) -> Result<()> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: pointers address initialized ucred and size storage with exact lengths.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
        || credential.uid != allowed_uid
        || credential.pid <= 0
    {
        return Err(Failure::Peer);
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(Failure::Protocol)
}
fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| Failure::Protocol)?;
        match stream.read(bytes) {
            Ok(0) => return Err(Failure::Protocol),
            Ok(count) => {
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Failure::Protocol),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_frame_by(stream: &mut UnixStream, deadline: Instant) -> Result<Request> {
    let mut size = [0; 4];
    read_until(stream, &mut size, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_REQUEST_BYTES {
        return Err(Failure::Protocol);
    }
    let mut bytes = vec![0; size];
    read_until(stream, &mut bytes, deadline)?;
    // Require request write-half closure: extra frames/bytes are never ignored.
    let mut trailing = [0];
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| Failure::Protocol)?;
    if stream.read(&mut trailing).map_err(|_| Failure::Protocol)? != 0 {
        return Err(Failure::Protocol);
    }
    remaining(deadline)?;
    parse_request(&bytes)
}
fn read_frame(stream: &mut UnixStream) -> Result<Request> {
    read_frame_by(stream, Instant::now() + Duration::from_secs(3))
}

fn write_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline).map_err(|_| Failure::Delivery)?))
            .map_err(|_| Failure::Delivery)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Failure::Delivery),
            Ok(count) => {
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Failure::Delivery),
        }
    }
    remaining(deadline).map_err(|_| Failure::Delivery)?;
    Ok(())
}

fn write_frame(stream: &mut UnixStream, value: &serde_json::Value) -> Result<()> {
    let bytes = fw_contracts::canonical_bytes(value).map_err(|_| Failure::Delivery)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Failure::Delivery);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    write_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_until(stream, &bytes, deadline)
}

struct Runtime {
    // Field drop order is significant: SQLite closes before the input files.
    store: AuthorityStore,
    config_input: PrivateInput,
    key_input: PrivateInput,
    config: Config,
    config_path: std::path::PathBuf,
    config_bytes: Zeroizing<Vec<u8>>,
    key: SigningKey,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    database_identity: DatabaseIdentity,
    worker_id: String,
}
impl Runtime {
    fn load(path: &Path) -> Result<Self> {
        let uid = identity()?;
        harden()?;
        let (config_input, config_bytes) = PrivateInput::open(path, uid, 16384)?;
        let config: Config = fw_contracts::parse_strict_with_limit(&config_bytes, 16384)
            .map_err(|_| Failure::Config)?;
        if config.schema_version != "fw.signer-config/v1"
            || config.signer_uid != uid
            || config.controller_uid == 0
            || config.controller_uid == uid
            || config.key_id.is_empty()
            || config.key_id.len() > 256
            || !config.key_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Failure::Config);
        }
        let tenant = AuthorityTenant::new(&config.org_id, &config.project_id)
            .map_err(|_| Failure::Config)?;
        let verifier = WebAuthn::new(&config.webauthn_origin).map_err(|_| Failure::Config)?;
        let (key_input, seed) =
            PrivateInput::open(Path::new(&config.key_file), uid, 32).map_err(|_| Failure::Key)?;
        let seed_array: &[u8; 32] = seed.as_slice().try_into().map_err(|_| Failure::Key)?;
        let key = SigningKey::from_bytes(seed_array);
        let input_identities = [config_input.identity, key_input.identity];
        let database_identity = check_database(&config, &input_identities)?;
        let store = AuthorityStore::open(&config.database_path).map_err(|_| Failure::Database)?;
        if check_database(&config, &input_identities)? != database_identity {
            return Err(Failure::Database);
        }
        Ok(Self {
            store,
            config_input,
            key_input,
            config,
            config_path: path.into(),
            config_bytes,
            key,
            tenant,
            verifier,
            database_identity,
            worker_id: uuid::Uuid::new_v4().to_string(),
        })
    }

    fn recheck(&self) -> Result<()> {
        if identity()? != self.config.signer_uid
            || *self
                .config_input
                .read(&self.config_path, self.config.signer_uid)?
                != *self.config_bytes
        {
            return Err(Failure::Config);
        }
        let seed = self
            .key_input
            .read(Path::new(&self.config.key_file), self.config.signer_uid)
            .map_err(|_| Failure::Key)?;
        if seed.as_slice() != self.key.as_bytes() {
            return Err(Failure::Key);
        }
        if check_database(
            &self.config,
            &[self.config_input.identity, self.key_input.identity],
        )? != self.database_identity
        {
            return Err(Failure::Database);
        }
        Ok(())
    }

    fn response(&mut self, request: Request) -> Result<serde_json::Value> {
        self.recheck()?;
        let request_id = request.validate()?.to_owned();
        match request {
            Request::Status { .. } => Ok(json!({
                "schema_version":"fw.signer-status/v1","request_id":request_id,
                "peer_identity_verified":true,"distinct_process_identity":true,
                "key_storage_permissions_verified":true,"signing_allowed":false,"dispatch_allowed":false,
                "production_blockers":["BUILD_IDENTITY_UNVERIFIED","NATIVE_QUALIFICATION_UNAVAILABLE"]
            })),
            Request::StatusV2 { .. } => Ok(json!({
                "schema_version":"fw.signer-status/v2","request_id":request_id,
                "peer_identity_verified":true,"distinct_process_identity":true,
                "key_storage_permissions_verified":true,"signing_allowed":false,"dispatch_allowed":false,
                "production_blockers":fw_authority::authority_gate_codes(&[
                    fw_authority::AuthorityGate::BuildIdentityRequired,
                    fw_authority::AuthorityGate::NativeQualificationRequired,
                ])
            })),
            Request::SignJob {
                job_id,
                expected_claim_generation,
                ..
            } => {
                let now = chrono::Utc::now().timestamp();
                let generation = expected_claim_generation
                    .parse()
                    .map_err(|_| Failure::Protocol)?;
                let result = self
                    .store
                    .sign_retained_job(
                        &self.tenant,
                        &self.verifier,
                        &job_id,
                        &self.worker_id,
                        generation,
                        &self.config.key_id,
                        &self.key,
                        now,
                    )
                    .map_err(|_| Failure::Authority)?;
                Ok(
                    json!({"schema_version":"fw.signer-outcome/v1","request_id":request_id,"signer_result":result}),
                )
            }
            Request::AuthorizeBootstrap { manifest_id, .. } => {
                let authorized = self
                    .store
                    .authorize_retained_bootstrap(
                        &self.tenant,
                        &manifest_id,
                        &self.config.key_id,
                        &self.key,
                        &self.verifier,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| Failure::Authority)?;
                Ok(
                    json!({"schema_version":"fw.signer-bootstrap-outcome/v1","request_id":request_id,
                    "authorization":authorized.authorization,"status":authorized.status}),
                )
            }
        }
    }
}

pub(super) fn serve(path: &Path) -> Result<()> {
    let mut runtime = Runtime::load(path)?;
    parent(
        Path::new(&runtime.config.socket_path),
        runtime.config.signer_uid,
    )
    .map_err(|_| Failure::Socket)?;
    // Never remove an existing object, including another live signer's socket.
    let listener = UnixListener::bind(&runtime.config.socket_path).map_err(|_| Failure::Socket)?;
    let metadata =
        fs::symlink_metadata(&runtime.config.socket_path).map_err(|_| Failure::Socket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != runtime.config.signer_uid
        || metadata.nlink() != 1
    {
        return Err(Failure::Socket);
    }
    // Other users may reach SO_PEERCRED admission, but only the configured
    // controller identity receives responses. No shared key group is required.
    fs::set_permissions(
        &runtime.config.socket_path,
        fs::Permissions::from_mode(0o666),
    )
    .map_err(|_| Failure::Socket)?;
    eprintln!("SIGNER_LISTENING production_signing=false production_dispatch=false");
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Failure::Socket),
        };
        if peer(&stream, runtime.config.controller_uid).is_err() {
            continue;
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| Failure::Socket)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| Failure::Socket)?;
        let request = match read_frame(&mut stream) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let request_id = request.validate()?.to_owned();
        let result = runtime.response(request).unwrap_or_else(|error| json!({
            "schema_version":"fw.signer-error/v1","request_id":request_id,"code":error.to_string()
        }));
        if write_frame(&mut stream, &result).is_err() {
            // A committed issuance stays committed. Lost output can never
            // refund a reservation, allocate a new grant or restore authority.
            eprintln!("SIGNER_DELIVERY_FAILED");
        }
    }
}

#[cfg(test)]
#[path = "linux_locking_tests.rs"]
mod locking_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_uses_kernel_identity_and_rejects_another_uid() {
        let (stream, _) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::getuid() };
        assert!(peer(&stream, uid).is_ok());
        assert_eq!(
            peer(&stream, uid.checked_add(1).unwrap()).unwrap_err(),
            Failure::Peer
        );
    }
    #[test]
    fn private_input_refuses_symlinks_hardlinks_and_shared_permissions() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::getuid() };
        let path = directory.path().join("key");
        // The managed test executor may map / and /tmp to an unrelated UID.
        // Exercise descriptor-relative leaf admission here; the disposable
        // Docker process suite exercises successful complete trusted path walks.
        let parent_fd = File::open(directory.path()).unwrap();
        let leaf = name(std::ffi::OsStr::new("key")).unwrap();
        fs::write(&path, [3; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_leaf(&parent_fd, &leaf, uid, 32).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(private_leaf(&parent_fd, &leaf, uid, 32).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            private_leaf(
                &parent_fd,
                &name(std::ffi::OsStr::new("link")).unwrap(),
                uid,
                32
            )
            .is_err()
        );
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(private_leaf(&parent_fd, &leaf, uid, 32).is_err());
        fs::remove_file(&link).unwrap();
        let dirlink = directory.path().join("dirlink");
        std::os::unix::fs::symlink(directory.path(), &dirlink).unwrap();
        assert!(private_file(&dirlink.join("key"), uid, 32).is_err());
    }
    #[test]
    fn framing_rejects_trailing_input_and_oversize_before_allocation() {
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        sender
            .write_all(&((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes())
            .unwrap();
        assert_eq!(read_frame(&mut receiver).unwrap_err(), Failure::Protocol);
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        let bytes = br#"{"operation":"status","schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001"}"#;
        sender
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        sender.write_all(bytes).unwrap();
        sender.write_all(b"x").unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(read_frame(&mut receiver).unwrap_err(), Failure::Protocol);
    }
    #[test]
    fn header_body_and_half_close_share_one_absolute_deadline() {
        for stage in ["header", "body", "half_close"] {
            let (mut receiver, mut sender) = UnixStream::pair().unwrap();
            let payload = br#"{"operation":"status","schema_version":"fw.signer-request/v1","request_id":"00000000-0000-4000-8000-000000000001"}"#;
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(payload);
            let worker = std::thread::spawn(move || {
                let immediate = match stage {
                    "header" => 0,
                    "body" => 4,
                    _ => wire.len(),
                };
                sender.write_all(&wire[..immediate]).unwrap();
                for byte in &wire[immediate..] {
                    std::thread::sleep(Duration::from_millis(15));
                    if sender.write_all(&[*byte]).is_err() {
                        break;
                    }
                }
                if stage == "half_close" {
                    std::thread::sleep(Duration::from_millis(150));
                }
            });
            let start = Instant::now();
            assert_eq!(
                read_frame_by(&mut receiver, start + Duration::from_millis(70)).unwrap_err(),
                Failure::Protocol
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            drop(receiver);
            worker.join().unwrap();
        }
    }
}
