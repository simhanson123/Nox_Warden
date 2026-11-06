//! Exact disposable nonloopback topology; this does not qualify a host backend.
use super::{Error, Result, native};
use fw_backend_linux::{
    BOOTSTRAP_PROFILE, BootstrapCapabilitySnapshot, BootstrapManagementBaseline,
    bootstrap_namespace_valid,
};
use serde_json::Value;
use std::{
    fs,
    fs::{File, OpenOptions},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
};

pub(super) struct Marker {
    file: File,
    identity: (u64, u64),
}
impl Marker {
    pub(super) fn load() -> Result<Self> {
        let directory = fs::symlink_metadata("/lab")?;
        if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o022 != 0 {
            return Err(Error::new("ISOLATED_BOOTSTRAP_REQUIRED"));
        }
        // Open once, before SQLite. Later guard checks never reopen this path.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/lab/DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE")?;
        let metadata = file.metadata()?;
        let marker = Self {
            file,
            identity: (metadata.dev(), metadata.ino()),
        };
        marker.recheck()?;
        Ok(marker)
    }
    fn recheck(&self) -> Result<()> {
        let check = || -> Result<()> {
            let metadata = fs::symlink_metadata("/lab/DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE")?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || (metadata.dev(), metadata.ino()) != self.identity
            {
                return Err(Error::new("ISOLATED_BOOTSTRAP_REQUIRED"));
            }
            Ok(())
        };
        check()?;
        let mut bytes = [0; 64];
        let length = self.file.read_at(&mut bytes, 0)?;
        if &bytes[..length] != b"fw-isolated-target-bootstrap-v1\n" {
            return Err(Error::new("ISOLATED_BOOTSTRAP_REQUIRED"));
        }
        check()
    }
}

pub(super) fn check(
    b: &BootstrapManagementBaseline,
    c: &BootstrapCapabilitySnapshot,
    marker: &Marker,
) -> Result<fw_backend_linux::ObservationContext> {
    b.validate()?;
    c.validate()?;
    marker.recheck()?;
    let outer = std::env::var("NOX_BOOTSTRAP_OUTER_NETNS")
        .map_err(|_| Error::new("ISOLATED_BOOTSTRAP_REQUIRED"))?;
    let observed = native::observation()?;
    if !bootstrap_namespace_valid(&outer)
        || outer == observed.network_namespace
        || observed.network_namespace != b.network_namespace
    {
        return Err(Error::new("BOOTSTRAP_NAMESPACE"));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapEff:\t", "CapPrm:\t", "CapBnd:\t"] {
        if status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            != Some(1u64 << 12)
        {
            return Err(Error::new("BOOTSTRAP_CAPABILITIES"));
        }
    }
    for field in ["CapInh:\t", "CapAmb:\t"] {
        if status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            != Some(0)
        {
            return Err(Error::new("BOOTSTRAP_CAPABILITIES"));
        }
    }
    if fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_tcp_loose")?.trim() != "0" {
        return Err(Error::new("BOOTSTRAP_CONNTRACK_PROFILE"));
    }
    let addresses: Value = serde_json::from_slice(&native::command(
        "/usr/sbin/ip",
        &["-j", "address", "show"],
        None,
    )?)
    .map_err(|_| Error::new("BOOTSTRAP_TOPOLOGY"))?;
    let interfaces = addresses
        .as_array()
        .ok_or(Error::new("BOOTSTRAP_TOPOLOGY"))?;
    if interfaces.len() != 2 {
        return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
    }
    let mut seen_loopback = false;
    let mut seen_target = false;
    for interface in interfaces {
        let values = interface["addr_info"]
            .as_array()
            .ok_or(Error::new("BOOTSTRAP_TOPOLOGY"))?;
        if interface["ifname"] == "lo" {
            if seen_loopback {
                return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
            }
            seen_loopback = true;
            for value in values {
                if !value["local"]
                    .as_str()
                    .and_then(|v| v.parse::<IpAddr>().ok())
                    .is_some_and(|v| v.is_loopback())
                {
                    return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
                }
            }
        } else if interface["ifname"] == b.interface_name {
            if seen_target
                || interface["ifindex"].as_u64() != Some(u64::from(b.interface_index))
                || values.len() != 1
                || values[0]["family"] != "inet"
                || values[0]["local"] != b.local_address
                || values[0]["prefixlen"].as_u64() != Some(u64::from(b.prefix_length))
            {
                return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
            }
            seen_target = true;
        } else {
            return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
        }
    }
    if !seen_loopback || !seen_target {
        return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
    }
    let local: Ipv4Addr = b
        .local_address
        .parse()
        .map_err(|_| Error::new("BOOTSTRAP_TOPOLOGY"))?;
    let network = u32::from(local) & !3;
    for family in ["-4", "-6"] {
        let routes: Value = serde_json::from_slice(&native::command(
            "/usr/sbin/ip",
            &["-j", family, "route", "show", "table", "all"],
            None,
        )?)
        .map_err(|_| Error::new("BOOTSTRAP_TOPOLOGY"))?;
        for route in routes.as_array().ok_or(Error::new("BOOTSTRAP_TOPOLOGY"))? {
            if route.get("gateway").is_some()
                || route.get("nexthops").is_some()
                || route.get("encap").is_some()
            {
                return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
            }
            let destination = route["dst"]
                .as_str()
                .ok_or(Error::new("BOOTSTRAP_TOPOLOGY"))?;
            let (address, prefix) = destination
                .split_once('/')
                .map_or((destination, None), |(a, p)| (a, Some(p)));
            let ip: IpAddr = address
                .parse()
                .map_err(|_| Error::new("BOOTSTRAP_TOPOLOGY"))?;
            let permitted = if route["dev"] == "lo" {
                ip.is_loopback() || ip.is_multicast()
            } else if route["dev"] == b.interface_name {
                matches!(ip,IpAddr::V4(v) if u32::from(v)&!3==network && match prefix{Some("30")=>u32::from(v)==network,Some("32")|None=>[network,network|3,u32::from(local)].contains(&u32::from(v)),_=>false})
            } else {
                false
            };
            if !permitted {
                return Err(Error::new("BOOTSTRAP_TOPOLOGY"));
            }
        }
    }
    let nft = String::from_utf8(native::command("/usr/sbin/nft", &["--version"], None)?)
        .map_err(|_| Error::new("BOOTSTRAP_CAPABILITY"))?;
    if c.platform != "linux"
        || c.backend != "nftables"
        || c.profile != BOOTSTRAP_PROFILE
        || c.architecture != std::env::consts::ARCH
        || c.kernel_release != fs::read_to_string("/proc/sys/kernel/osrelease")?.trim()
        || c.nft_version != nft.trim()
    {
        return Err(Error::new("BOOTSTRAP_CAPABILITY"));
    }
    native::observation()
}
