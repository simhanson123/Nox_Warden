//! Native qualification preflight and explicit isolated loopback smoke runner.
//! Full incomplete platform qualification remains NOT_RUN; smoke writes rules
//! only inside a disposable Docker network namespace and reports its own scope.
use serde::Serialize;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Serialize)]
struct Check {
    id: String,
    status: String,
    reason: String,
}
#[derive(Serialize)]
struct Report {
    schema_version: String,
    backend: String,
    status: String,
    exit_code: u8,
    commit: Option<String>,
    os: String,
    architecture: String,
    generated_at_unix: u64,
    checks: Vec<Check>,
    packet_tests_executed: usize,
    firewall_modified: bool,
}
fn output(command: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(command).args(args).output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}
fn effective_capability(index: u32) -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("CapEff:\t")
                    .and_then(|x| u64::from_str_radix(x, 16).ok())
            })
        })
        .is_some_and(|n| n & (1 << index) != 0)
}
fn report(backend: &str) -> Report {
    let mut checks = Vec::new();
    let target_os = match backend {
        "nftables" => "linux",
        "windows_wfp" => "windows",
        _ => "macos",
    };
    if env::consts::OS != target_os {
        checks.push(Check {
            id: "native_os".into(),
            status: "NOT_RUN".into(),
            reason: format!("Requires {target_os}; current host is {}", env::consts::OS),
        });
    }
    if backend == "nftables" && env::consts::OS == "linux" {
        let nft = output("nft", &["--version"]);
        checks.push(Check {
            id: "nft_binary".into(),
            status: if nft.is_some() {
                "AVAILABLE"
            } else {
                "MISSING"
            }
            .into(),
            reason: nft.unwrap_or_else(|| "nft executable unavailable".into()),
        });
        for (id, bit) in [
            ("CAP_NET_ADMIN", 12),
            ("CAP_NET_RAW", 13),
            ("CAP_SYS_ADMIN_for_namespace", 21),
        ] {
            let present = effective_capability(bit);
            checks.push(Check {
                id: id.into(),
                status: if present { "PRESENT" } else { "MISSING" }.into(),
                reason:
                    "Read from /proc/self/status; capability presence is not fixture qualification"
                        .into(),
            });
        }
    }
    checks.push(Check{id:"native_suite".into(),status:"NOT_RUN".into(),reason:match backend{
        "nftables"=>"An isolated Linux loopback smoke suite is available via the smoke subcommand. Full native service, physical NIC, fragment/PMTU, installer and recovery-watchdog qualification remain incomplete.",
        "windows_wfp"=>"WFP service/callout driver, WDK build, signed installer and isolated Windows packet/crash fixtures are not implemented.",
        _=>"Network Extension packet provider, authenticated XPC, entitlements/notarization and actual Mac packet/crash/boot fixtures are not implemented."
    }.into()});
    Report {
        schema_version: "fw.native-qualification-report/v1".into(),
        backend: backend.into(),
        status: "NOT_RUN".into(),
        exit_code: 2,
        commit: output("git", &["rev-parse", "HEAD"]),
        os: env::consts::OS.into(),
        architecture: env::consts::ARCH.into(),
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        checks,
        packet_tests_executed: 0,
        firewall_modified: false,
    }
}
fn args(args: &[String]) -> Result<(String, String, PathBuf), String> {
    if args.len() != 5
        || !["qualify", "smoke"].contains(&args[0].as_str())
        || (args[0] == "smoke" && args[2] != "nftables")
        || args[1] != "--backend"
        || args[3] != "--report"
        || !["nftables", "windows_wfp", "macos_network_extension"].contains(&args[2].as_str())
    {
        return Err("Usage: fw_testlab qualify --backend nftables|windows_wfp|macos_network_extension --report PATH; or fw_testlab smoke --backend nftables --report PATH".into());
    }
    Ok((args[0].clone(), args[2].clone(), PathBuf::from(&args[4])))
}
fn save(path: &Path, report: &Report) -> io::Result<()> {
    if let Some(p) = path.parent() {
        if !p.as_os_str().is_empty() {
            fs::create_dir_all(p)?;
        }
    }
    let bytes = serde_json::to_vec_pretty(report).map_err(io::Error::other)?;
    fs::write(path, bytes)
}
fn main() -> ExitCode {
    let (action, backend, path) = match args(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(64);
        }
    };
    if action == "smoke" {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/linux-lab.py");
        return match Command::new("python3")
            .arg(script)
            .arg("--report")
            .arg(&path)
            .status()
        {
            Ok(status) => ExitCode::from(match status.code() {
                Some(code @ 0..=2) => code as u8,
                _ => 1,
            }),
            Err(error) => {
                eprintln!("Cannot start isolated packet lab: {error}");
                ExitCode::from(1)
            }
        };
    }
    let report = report(&backend);
    if let Err(e) = save(&path, &report) {
        eprintln!("Cannot write evidence: {e}");
        return ExitCode::from(1);
    }
    println!(
        "NOT_RUN: {} native qualification. Evidence: {}. No firewall state changed.",
        backend,
        path.display()
    );
    ExitCode::from(2)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_backend_rejected() {
        assert!(
            args(&["qualify", "--backend", "mock", "--report", "out.json"].map(String::from))
                .is_err()
        );
    }
    #[test]
    fn native_report_never_claims_unexecuted_packets_passed() {
        for b in ["nftables", "windows_wfp", "macos_network_extension"] {
            let r = report(b);
            assert_eq!(r.status, "NOT_RUN");
            assert_eq!(r.exit_code, 2);
            assert_eq!(r.packet_tests_executed, 0);
            assert!(!r.firewall_modified);
        }
    }
    #[test]
    fn smoke_cannot_be_mislabeled_as_windows_qualification() {
        assert!(args(
            &["smoke", "--backend", "windows_wfp", "--report", "out.json"].map(String::from)
        )
        .is_err());
        let (action, backend, _) =
            args(&["smoke", "--backend", "nftables", "--report", "out.json"].map(String::from))
                .unwrap();
        assert_eq!(action, "smoke");
        assert_eq!(backend, "nftables");
    }
}
