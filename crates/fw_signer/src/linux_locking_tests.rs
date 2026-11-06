//! Real cross-process POSIX lock regressions. SQLite owns every DB descriptor.
use super::*;
use std::process::{Command, Stdio};

const NOW: i64 = 1_800_000_000;
const MAIN_SHARED_START: libc::off_t = 1_073_741_826;
const MAIN_SHARED_LENGTH: libc::off_t = 510;

fn save_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn directory() -> (tempfile::TempDir, File) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fd = File::open(directory.path()).unwrap();
    (directory, fd)
}

fn leaf(value: &str) -> CString {
    name(std::ffi::OsStr::new(value)).unwrap()
}

fn input_at(directory: &File, name: &str, maximum: usize, uid: u32) -> PrivateInput {
    // Open before SQLite, using the same validated leaf opener as startup. The
    // full trusted ancestor walk is exercised in the disposable process lab.
    let file = private_leaf(directory, &leaf(name), uid, maximum).unwrap();
    let metadata = file.metadata().unwrap();
    PrivateInput {
        file,
        identity: (metadata.dev(), metadata.ino()),
        maximum,
    }
}

fn probe(path: &Path, start: libc::off_t, length: libc::off_t) -> i32 {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "linux::locking_tests::external_lock_probe",
        ])
        .env("FW_SIGNER_LOCK_PROBE_PATH", path)
        .env("FW_SIGNER_LOCK_PROBE_START", start.to_string())
        .env("FW_SIGNER_LOCK_PROBE_LENGTH", length.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .code()
        .expect("lock probe terminated by signal")
}

#[test]
#[ignore = "subprocess helper; invoked by the real lock regression"]
fn external_lock_probe() {
    let path = std::env::var_os("FW_SIGNER_LOCK_PROBE_PATH").unwrap();
    let start: libc::off_t = std::env::var("FW_SIGNER_LOCK_PROBE_START")
        .unwrap()
        .parse()
        .unwrap();
    let length: libc::off_t = std::env::var("FW_SIGNER_LOCK_PROBE_LENGTH")
        .unwrap()
        .parse()
        .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    // SAFETY: flock contains scalar integer fields; all fields and padding are
    // initialized before the kernel inspects the nonblocking F_SETLK request.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start;
    lock.l_len = length;
    // SAFETY: file is live and lock is fully initialized with a valid range.
    let code = if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == 0 {
        20 // Acquired. Closing this child cannot affect the parent's locks.
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) | Some(libc::EAGAIN) => 21, // Blocked.
            _ => 22,
        }
    };
    std::process::exit(code);
}

#[test]
fn metadata_checker_preserves_live_sqlite_main_and_dms_locks_even_after_input_alias_refusal() {
    let (directory, parent_fd) = directory();
    let uid = unsafe { libc::getuid() };
    let database = directory.path().join("authority.sqlite3");
    let shm = directory.path().join("authority.sqlite3-shm");
    let control = directory.path().join("unlocked");
    save_private(&control, &[0; 256]);
    assert_eq!(probe(&control, 128, 1), 20, "unlocked positive control");
    assert_eq!(
        probe(&control, MAIN_SHARED_START, MAIN_SHARED_LENGTH),
        20,
        "main range positive control"
    );

    let config = directory.path().join("signer.json");
    let seed = directory.path().join("seed");
    save_private(&config, b"original private configuration");
    save_private(&seed, &[42; 32]);
    let config_input = input_at(&parent_fd, "signer.json", 16384, uid);
    let key_input = input_at(&parent_fd, "seed", 32, uid);
    let input_identities = [config_input.identity, key_input.identity];
    // This store is created after the retained input descriptors and therefore
    // drops first. No raw SQLite connection or synthetic fcntl lock is used.
    let mut store = AuthorityStore::open(&database).unwrap();
    let tenant = AuthorityTenant::new(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    )
    .unwrap();
    store
        .provision_target_metadata_project(&tenant, NOW)
        .unwrap();
    assert!(
        store
            .read_registry_object(
                &tenant,
                "bootstrap_manifest",
                "33333333-3333-4333-8333-333333333333",
                NOW,
            )
            .unwrap()
            .is_none()
    );
    let assert_locks = |main: &Path, shm: &Path| {
        assert_eq!(probe(shm, 128, 1), 21, "SQLite DMS must remain locked");
        assert_eq!(
            probe(main, MAIN_SHARED_START, MAIN_SHARED_LENGTH),
            21,
            "SQLite main shared range must remain locked"
        );
    };
    assert_locks(&database, &shm);
    for _ in 0..3 {
        database_at(
            &parent_fd,
            &leaf("authority.sqlite3"),
            uid,
            &input_identities,
        )
        .unwrap();
        assert_locks(&database, &shm);
    }

    for (path, input) in [(&config, &config_input), (&seed, &key_input)] {
        let input_leaf = leaf(path.file_name().unwrap().to_str().unwrap());
        let held = directory.path().join("retained-input");
        fs::rename(path, &held).unwrap();
        for sqlite_path in [&database, &shm] {
            fs::hard_link(sqlite_path, path).unwrap();
            assert!(input.read_at(&parent_fd, &input_leaf, uid).is_err());
            assert_locks(&database, &shm);
            fs::remove_file(path).unwrap();
            fs::rename(sqlite_path, path).unwrap();
            assert!(input.read_at(&parent_fd, &input_leaf, uid).is_err());
            if sqlite_path == &database {
                assert_locks(path, &shm);
            } else {
                assert_locks(&database, path);
            }
            fs::rename(path, sqlite_path).unwrap();
        }
        fs::rename(&held, path).unwrap();
        assert!(input.read_at(&parent_fd, &input_leaf, uid).is_ok());
        assert_locks(&database, &shm);
    }
    drop(store);
}

#[test]
fn metadata_only_database_admission_refuses_unsafe_main_and_sidecar_leaves() {
    let (directory, parent_fd) = directory();
    let uid = unsafe { libc::getuid() };
    let database_leaf = leaf("database");
    for name in ["database", "database-wal", "database-shm"] {
        save_private(&directory.path().join(name), &[0; 32]);
    }
    let identity = database_at(&parent_fd, &database_leaf, uid, &[]).unwrap();
    assert!(database_at(&parent_fd, &database_leaf, uid, &[identity]).is_err());
    for name in ["database", "database-wal", "database-shm"] {
        let path = directory.path().join(name);
        for mode in [0o640, 0o200] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(database_at(&parent_fd, &database_leaf, uid, &[]).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let other = directory.path().join("other");
        fs::hard_link(&path, &other).unwrap();
        assert!(database_at(&parent_fd, &database_leaf, uid, &[]).is_err());
        fs::remove_file(&other).unwrap();
        fs::rename(&path, &other).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(database_at(&parent_fd, &database_leaf, uid, &[]).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(&other, &path).unwrap();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(512 * 1024 * 1024 + 1).unwrap();
        assert!(database_at(&parent_fd, &database_leaf, uid, &[]).is_err());
        file.set_len(32).unwrap();
    }
    fs::remove_file(directory.path().join("database-wal")).unwrap();
    fs::remove_file(directory.path().join("database-shm")).unwrap();
    assert_eq!(
        database_at(&parent_fd, &database_leaf, uid, &[]).unwrap(),
        identity
    );
    fs::remove_file(directory.path().join("database")).unwrap();
    assert!(database_at(&parent_fd, &database_leaf, uid, &[]).is_err());
}
