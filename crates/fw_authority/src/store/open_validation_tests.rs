//! Existing-store validation holds a read snapshot, so WAL writers can commit
//! during retained verification. Timing is synchronized at the validation hook;
//! this does not rely on a large fixture or scheduler speed.
use super::*;
use signing_test_support::{Fixture, NOW};
use std::sync::mpsc;

#[test]
fn open_and_current_maintenance_allow_a_writer_during_validation() {
    for maintenance in [false, true] {
        let mut f = Fixture::new();
        let path = f.path.clone();
        let backup = f.directory.path().join("unused-backup.sqlite3");
        let (started, reading) = mpsc::channel();
        let (resume, waiting) = mpsc::channel();
        let validator = std::thread::spawn(move || {
            migrations::OPEN_VALIDATION_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    started.send(()).unwrap();
                    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
                }));
            });
            if maintenance {
                AuthorityStore::migrate(&path, &backup)
            } else {
                AuthorityStore::open(&path).map(drop)
            }
        });
        reading.recv_timeout(Duration::from_secs(10)).unwrap();
        f.store
            .connection
            .busy_timeout(Duration::from_millis(100))
            .unwrap();
        let wrote = f.store.provision_principal(
            &f.tenant,
            "90000000-0000-4000-8000-000000000001",
            "https://concurrent.fixture.example",
            "90000000-0000-4000-8000-000000000001",
            NOW,
        );
        // Always release the paused reader before asserting, including on a
        // regression where an IMMEDIATE validation would block this writer.
        resume.send(()).unwrap();
        let validated = validator.join().unwrap();
        assert!(wrote.is_ok(), "maintenance={maintenance}: {wrote:?}");
        assert!(
            validated.is_ok(),
            "maintenance={maintenance}: {validated:?}"
        );
        assert!(!f.directory.path().join("unused-backup.sqlite3").exists());
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn read_only_open_and_current_maintenance_reject_retained_corruption_without_repair() {
    let f = Fixture::new();
    drop(f.store);
    let mut db = Connection::open(&f.path).unwrap();
    let guard: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_audit_no_update'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch("DROP TRIGGER authority_audit_no_update")
        .unwrap();
    tx.execute("UPDATE authority_audit SET canonical_bytes=x'7b7d' WHERE rowid=(SELECT MIN(rowid) FROM authority_audit)", []).unwrap();
    tx.execute_batch(&guard).unwrap();
    tx.commit().unwrap();
    let before: Vec<(i64, Vec<u8>)> = db
        .prepare("SELECT rowid,canonical_bytes FROM authority_audit ORDER BY rowid")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(AuthorityStore::open(&f.path).is_err());
    let backup = f.directory.path().join("no-repair.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert!(!backup.exists());
    assert!(!backup.with_extension("manifest.json").exists());
    let after: Vec<(i64, Vec<u8>)> = db
        .prepare("SELECT rowid,canonical_bytes FROM authority_audit ORDER BY rowid")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(before, after);
    let retained: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_audit_no_update'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, guard);
}

#[test]
fn live_peer_refresh_validates_without_holding_the_writer_reservation() {
    let mut f = Fixture::new();
    let path = f.path.clone();
    let tenant = f.tenant.clone();
    let mut stale = AuthorityStore::open(&path).unwrap();
    // Invalidate this connection's marker with an ordinary healthy peer commit.
    f.store
        .provision_principal(
            &tenant,
            "90000000-0000-4000-8000-000000000002",
            "https://refresh.fixture.example",
            "90000000-0000-4000-8000-000000000002",
            NOW,
        )
        .unwrap();
    let (started, reading) = mpsc::channel();
    let (resume, waiting) = mpsc::channel();
    let validator = std::thread::spawn(move || {
        migrations::OPEN_VALIDATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                started.send(()).unwrap();
                waiting.recv_timeout(Duration::from_secs(10)).unwrap();
            }));
        });
        let outcome = stale.provision_principal(
            &tenant,
            "90000000-0000-4000-8000-000000000003",
            "https://refresh.fixture.example",
            "90000000-0000-4000-8000-000000000003",
            NOW,
        );
        // A peer committed during our validated read snapshot. It is safe to
        // retry against a new checked snapshot or to refuse this attempt.
        if outcome.is_err() {
            stale
                .provision_principal(
                    &tenant,
                    "90000000-0000-4000-8000-000000000003",
                    "https://refresh.fixture.example",
                    "90000000-0000-4000-8000-000000000003",
                    NOW,
                )
                .unwrap();
        }
    });
    reading.recv_timeout(Duration::from_secs(10)).unwrap();
    f.store
        .connection
        .busy_timeout(Duration::from_millis(100))
        .unwrap();
    let wrote = f.store.provision_principal(
        &f.tenant,
        "90000000-0000-4000-8000-000000000004",
        "https://refresh.fixture.example",
        "90000000-0000-4000-8000-000000000004",
        NOW,
    );
    resume.send(()).unwrap();
    validator.join().unwrap();
    assert!(wrote.is_ok(), "peer write during refresh: {wrote:?}");
    AuthorityStore::open(&f.path).unwrap();
}
