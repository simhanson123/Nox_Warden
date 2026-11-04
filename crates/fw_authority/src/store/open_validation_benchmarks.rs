//! Manual, reproducible retained-open benchmark. Fixture creation uses reviewed
//! plans, genuine test-authority intents and public unissued cancellation; no
//! trigger removal, rewritten indexes or synthetic quota rows. This mechanics
//! fixture is not production signing or native-kernel qualification.
use super::*;
use signing_test_support::{Fixture, NOW, native};

fn advance_plan(f: &mut Fixture, generation: u64) {
    let mut plan = f.plan.clone();
    plan["plan_id"] = new_id().unwrap().into();
    plan["target_generation"] = generation.to_string().into();
    let id = plan["plan_id"].as_str().unwrap().to_owned();
    f.store
        .register_reviewed_plan(&f.tenant, &plan, &f.requirements, &f.review, NOW)
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, &id, 1, NOW)
        .unwrap();
    let compiled = fw_native_evidence::compile_evidence(&plan, &f.review, &f.references).unwrap();
    let installation = native::installation(compiled.baseline(), NOW);
    let challenge = f
        .store
        .challenge_native_observation(
            &f.tenant,
            &id,
            fw_native_evidence::ArtifactRole::Baseline,
            &installation,
            Some(&f.baseline_receipt_hash),
            1,
            generation,
            NOW,
        )
        .unwrap();
    let proof = native::proof(
        &challenge,
        installation.clone(),
        native::snapshot(&installation.native),
        NOW,
    );
    let observation = f
        .store
        .admit_native_observation(&f.tenant, &proof, NOW)
        .unwrap();
    f.plan = plan;
    f.baseline_receipt_hash = observation.receipt_hash;
    f.current_approval_hash = f.approve(&id, NOW);
}

fn measure(path: &Path, count: usize) {
    let rows: (i64, i64, i64) = Connection::open(path).unwrap().query_row(
        "SELECT (SELECT count(*) FROM authority_signing_quota_reservations),(SELECT count(*) FROM authority_signing_jobs),(SELECT count(*) FROM authority_audit)",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(rows.0, count as i64);
    assert_eq!(rows.1, count as i64);
    for sample in 0..3 {
        let start = Instant::now();
        drop(AuthorityStore::open(path).unwrap());
        eprintln!(
            "OPEN_BENCH profile={} cancelled={} jobs={} audit={} sample={} elapsed_us={}",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            count,
            rows.1,
            rows.2,
            sample,
            start.elapsed().as_micros()
        );
    }
}

#[test]
#[ignore = "manual performance fixture; env FW_OPEN_BENCH_DIR is a private output directory"]
fn retained_open_genuine_cancelled_scaling() {
    let directory = std::path::PathBuf::from(std::env::var_os("FW_OPEN_BENCH_DIR").unwrap());
    if std::env::var_os("FW_OPEN_BENCH_READ_EXISTING").is_some() {
        for count in [0, 100, 500] {
            measure(&directory.join(format!("cancelled-{count}.sqlite3")), count);
        }
        return;
    }
    fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut f = Fixture::new();
    for count in 0..=500 {
        if [0, 100, 500].contains(&count) {
            let output = directory.join(format!("cancelled-{count}.sqlite3"));
            assert!(!output.exists(), "benchmark output must be new");
            Connection::open(&f.path)
                .unwrap()
                .backup("main", &output, None)
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
            }
            measure(&output, count);
        }
        if count == 500 {
            break;
        }
        if count > 0 {
            advance_plan(&mut f, count as u64 + 1);
        }
        let intent = signing_intents::test_prepare(&mut f, NOW);
        f.store
            .cancel_signing_job(&f.tenant, &intent.intent.job_id, NOW)
            .unwrap();
    }
}
