use crate::{Error, Result};
use fw_backend_linux::{BindingContext, ObservationContext};
use fw_contracts::{MAX_INTERNAL_BYTES, canonical_bytes, parse_value_with_limit};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new("CLOCK_UNTRUSTED"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| Error::new("CLOCK_UNTRUSTED"))
}
pub fn monotonic_millis() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is writable and CLOCK_BOOTTIME includes suspend time.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0
        || ts.tv_sec < 0
        || ts.tv_nsec < 0
    {
        return Err(Error::new("CLOCK_UNTRUSTED"));
    }
    (ts.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|v| v.checked_add(ts.tv_nsec as u64 / 1_000_000))
        .ok_or(Error::new("CLOCK_UNTRUSTED"))
}
pub fn observation() -> Result<ObservationContext> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into();
    let network_namespace = fs::read_link("/proc/self/ns/net")?
        .to_string_lossy()
        .into_owned();
    // The monotonic horizon begins before the wall sample. Long descheduling or
    // suspend between clock reads cannot silently consume the uncertainty bound.
    let before = monotonic_millis()?;
    let wall_time_unix = now()?;
    let after = monotonic_millis()?;
    if after
        .checked_sub(before)
        .is_none_or(|elapsed| elapsed > 1000)
    {
        return Err(Error::new("CLOCK_SAMPLE_UNCERTAIN"));
    }
    Ok(ObservationContext {
        boot_id,
        network_namespace,
        wall_time_unix,
        monotonic_millis: before,
    })
}
pub fn binding(operation_id: &str, grant_hash: &str) -> Result<BindingContext> {
    let observed = observation()?;
    Ok(BindingContext {
        operation_id: operation_id.into(),
        grant_hash: grant_hash.into(),
        boot_id: observed.boot_id,
        network_namespace: observed.network_namespace,
        wall_time_unix: observed.wall_time_unix,
        monotonic_millis: observed.monotonic_millis,
        clock_uncertainty_seconds: 1,
        elapsed_seconds: 0,
        commit_budget_seconds: 5,
    })
}
pub fn guard() -> Result<ObservationContext> {
    let marker = fs::read("/lab/DISPOSABLE_NETWORK_NAMESPACE")?;
    if marker != b"nox-linux-loopback-lab-v1\n" {
        return Err(Error::new("ISOLATED_LAB_REQUIRED"));
    }
    let observed = observation()?;
    let outer =
        std::env::var("NOX_LAB_OUTER_NETNS").map_err(|_| Error::new("ISOLATED_LAB_REQUIRED"))?;
    if outer == observed.network_namespace || !outer.starts_with("net:[") {
        return Err(Error::new("OUTER_NAMESPACE_REFUSED"));
    }
    let mut interfaces = fs::read_dir("/sys/class/net")?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<Vec<_>>>()?;
    interfaces.sort();
    if interfaces != ["lo"] {
        return Err(Error::new("NON_LOOPBACK_INTERFACE"));
    }
    let process_status = fs::read_to_string("/proc/self/status")?;
    let capabilities = process_status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|s| u64::from_str_radix(s, 16).ok());
    if capabilities != Some(1 << 12) {
        return Err(Error::new("ISOLATED_CAPABILITIES_REQUIRED"));
    }
    let addresses = command("/usr/sbin/ip", &["-j", "address", "show"], None)?;
    let addresses: Value =
        serde_json::from_slice(&addresses).map_err(|_| Error::new("ISOLATION_OBSERVATION"))?;
    for interface in addresses
        .as_array()
        .ok_or(Error::new("ISOLATION_OBSERVATION"))?
    {
        if interface["ifname"] != "lo" {
            return Err(Error::new("NON_LOOPBACK_INTERFACE"));
        }
        for address in interface["addr_info"]
            .as_array()
            .ok_or(Error::new("ISOLATION_OBSERVATION"))?
        {
            let local = address["local"]
                .as_str()
                .ok_or(Error::new("ISOLATION_OBSERVATION"))?;
            if !local
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            {
                return Err(Error::new("NON_LOOPBACK_ADDRESS"));
            }
        }
    }
    for family in ["-4", "-6"] {
        let bytes = command(
            "/usr/sbin/ip",
            &["-j", family, "route", "show", "table", "all"],
            None,
        )?;
        let routes: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::new("ISOLATION_ROUTES"))?;
        for route in routes.as_array().ok_or(Error::new("ISOLATION_ROUTES"))? {
            let destination = route["dst"]
                .as_str()
                .ok_or(Error::new("ISOLATION_ROUTES"))?;
            let address = destination
                .split('/')
                .next()
                .ok_or(Error::new("ISOLATION_ROUTES"))?;
            let permitted = address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip.is_multicast());
            if route["dev"] != "lo" || route.get("gateway").is_some() || !permitted {
                return Err(Error::new("NON_LOOPBACK_ROUTE"));
            }
        }
    }
    if fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_tcp_loose")?.trim() != "0" {
        return Err(Error::new("CONNTRACK_PROFILE_MISMATCH"));
    }
    observation()
}
/// Fixed program/argument callers only. Output and run time are bounded, no shell.
pub fn command(program: &str, arguments: &[&str], input: Option<Vec<u8>>) -> Result<Vec<u8>> {
    if !["/usr/sbin/ip", "/usr/sbin/nft"].contains(&program) || !Path::new(program).is_file() {
        return Err(Error::new("NATIVE_BINARY_UNAVAILABLE"));
    }
    let mut child = Command::new(program)
        .args(arguments)
        .env("TZ", "UTC")
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().expect("piped stdin");
        thread::spawn(move || stdin.write_all(&bytes))
    });
    let stdout = child.stdout.take().ok_or(Error::new("NATIVE_PIPE"))?;
    let stderr = child.stderr.take().ok_or(Error::new("NATIVE_PIPE"))?;
    let output = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_INTERNAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => {
                // SAFETY: this is the process group created for this child.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                break None;
            }
        }
        if started.elapsed() >= Duration::from_secs(2) {
            // SAFETY: negative pid is the process group created for this child.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let bytes = output.join().map_err(|_| Error::new("NATIVE_PIPE"))??;
    let errors = errors.join().map_err(|_| Error::new("NATIVE_PIPE"))??;
    if status.is_none() {
        return Err(Error::new("NATIVE_TIMEOUT"));
    }
    if !status.is_some_and(|status| status.success())
        || bytes.len() > MAX_INTERNAL_BYTES
        || errors.len() > 4096
    {
        return Err(Error::new("NATIVE_COMMAND_FAILED"));
    }
    Ok(bytes)
}
pub fn readback(table: &str) -> Result<Value> {
    if table.len() != 27
        || !table.starts_with("fw_")
        || !table[3..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(Error::new("TABLE_ID"));
    }
    let bytes = command(
        "/usr/sbin/nft",
        &["-j", "list", "table", "inet", table],
        None,
    )?;
    parse_value_with_limit(&bytes, MAX_INTERNAL_BYTES).map_err(|_| Error::new("NATIVE_JSON"))
}
pub fn replace(
    table: &str,
    nft_json: &Value,
    binding: &BindingContext,
    authority_deadline: i64,
) -> Result<()> {
    let mut commands = vec![json!({"delete":{"table":{"family":"inet","name":table}}})];
    commands.extend(
        nft_json["nftables"]
            .as_array()
            .ok_or(Error::new("NATIVE_ARTIFACT"))?
            .iter()
            .cloned(),
    );
    let bytes = canonical_bytes(&json!({"nftables":commands}))
        .map_err(|_| Error::new("NATIVE_ARTIFACT"))?;
    // Serialization and every durable journal write precede this final clock
    // sample. Leave the complete bounded nft process budget before the original
    // binding deadline; a slow preparation cannot enlarge a token lifetime.
    let observed = observation()?;
    let elapsed = observed
        .monotonic_millis
        .checked_sub(binding.monotonic_millis)
        .ok_or(Error::new("INSTALLATION_BUDGET_EXPIRED"))?;
    if observed.boot_id != binding.boot_id
        || observed.network_namespace != binding.network_namespace
        || elapsed.saturating_add(2000) > binding.commit_budget_seconds.saturating_mul(1000)
        || observed.wall_time_unix < binding.wall_time_unix
        || observed.wall_time_unix >= authority_deadline
    {
        return Err(Error::new("INSTALLATION_BUDGET_EXPIRED"));
    }
    command("/usr/sbin/nft", &["-j", "-f", "-"], Some(bytes))?;
    Ok(())
}
