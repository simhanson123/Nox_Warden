//! Pure F-2.0 policy semantics. No clocks, credentials, persistence or OS writes.
//! Native adapters must supply a verified original flow tuple, including reply
//! direction/conntrack association; this evaluator does not infer that evidence.
use chrono::NaiveDateTime;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use unicode_normalization::UnicodeNormalization;

pub const MAX_ALLOW_SECONDS: i64 = 86_400;
pub const MAX_REVIEW_SECONDS: i64 = 90 * 86_400;
pub const MAX_CIDRS: usize = 256;
pub const MAX_PORT_RANGES: usize = 64; // The core contract is stricter than the global API cap.

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct DomainError(pub &'static str);

pub type Result<T> = std::result::Result<T, DomainError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Input,
    Output,
    Forward,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase", deny_unknown_fields)]
pub enum Transport {
    Tcp {
        destination_ports: Vec<PortRange>,
    },
    Udp {
        destination_ports: Vec<PortRange>,
    },
    Icmp {
        #[serde(rename = "type")]
        icmp_type: u8,
        code: u8,
    },
    Icmpv6 {
        #[serde(rename = "type")]
        icmp_type: u8,
        code: u8,
    },
}

impl Transport {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Tcp { .. } => Protocol::Tcp,
            Self::Udp { .. } => Protocol::Udp,
            Self::Icmp { .. } => Protocol::Icmp,
            Self::Icmpv6 { .. } => Protocol::Icmpv6,
        }
    }
    pub fn ports(&self) -> Option<&[PortRange]> {
        match self {
            Self::Tcp { destination_ports } | Self::Udp { destination_ports } => {
                Some(destination_ports)
            }
            _ => None,
        }
    }
    fn validate(&self, family: Family) -> Result<()> {
        if (self.protocol() == Protocol::Icmp && family != Family::Ipv4)
            || (self.protocol() == Protocol::Icmpv6 && family != Family::Ipv6)
        {
            return Err(DomainError("FAMILY_MISMATCH"));
        }
        if let Some(ports) = self.ports() {
            if ports.is_empty() || ports.len() > MAX_PORT_RANGES {
                return Err(DomainError("PORT_RANGE_LIMIT"));
            }
            let mut sorted = ports.to_vec();
            sorted.sort();
            if sorted.iter().any(|p| p.start == 0 || p.start > p.end) {
                return Err(DomainError("INVALID_PORT_RANGE"));
            }
            if sorted.windows(2).any(|p| p[0].end >= p[1].start) {
                return Err(DomainError("OVERLAPPING_PORT_RANGES"));
            }
        }
        Ok(())
    }
    fn normalized(&self) -> Self {
        let mut result = self.clone();
        match &mut result {
            Self::Tcp { destination_ports } | Self::Udp { destination_ports } => {
                destination_ports.sort()
            }
            _ => {}
        }
        result
    }
    fn intersection(&self, other: &Self) -> Option<Self> {
        if self.protocol() != other.protocol() {
            return None;
        }
        match (self.ports(), other.ports()) {
            (Some(a), Some(b)) => {
                let mut ports = Vec::new();
                for x in a {
                    for y in b {
                        let p = PortRange {
                            start: x.start.max(y.start),
                            end: x.end.min(y.end),
                        };
                        if p.start <= p.end {
                            ports.push(p);
                        }
                    }
                }
                ports.sort();
                ports.dedup();
                if ports.is_empty() {
                    None
                } else if self.protocol() == Protocol::Tcp {
                    Some(Self::Tcp {
                        destination_ports: ports,
                    })
                } else {
                    Some(Self::Udp {
                        destination_ports: ports,
                    })
                }
            }
            _ => {
                if self == other {
                    Some(self.clone())
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub family: Family,
    pub direction: Direction,
    pub source_asset_ids: Vec<String>,
    pub destination_asset_ids: Vec<String>,
    pub source_cidrs: Vec<String>,
    pub destination_cidrs: Vec<String>,
    pub transport: Transport,
    pub ingress_interfaces: Vec<String>,
    pub egress_interfaces: Vec<String>,
}

pub fn validate_uuid(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| DomainError("INVALID_UUID"))?;
    if parsed.hyphenated().to_string() != value {
        return Err(DomainError("NONCANONICAL_UUID"));
    }
    Ok(())
}

pub fn timestamp(value: &str) -> Result<i64> {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit())
        || &value[17..19] >= "60"
    {
        return Err(DomainError("INVALID_TIMESTAMP"));
    }
    let time = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| DomainError("INVALID_TIMESTAMP"))?;
    if time.format("%Y-%m-%dT%H:%M:%SZ").to_string() != value {
        return Err(DomainError("INVALID_TIMESTAMP"));
    }
    Ok(time.and_utc().timestamp())
}

fn unique_strings(values: &[String], minimum: usize, maximum: usize) -> Result<()> {
    if values.len() < minimum || values.len() > maximum {
        return Err(DomainError("COLLECTION_LIMIT"));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(DomainError("DUPLICATE_SET_ITEM"));
    }
    Ok(())
}

fn networks(values: &[String], family: Family) -> Result<Vec<IpNet>> {
    unique_strings(values, 1, MAX_CIDRS)?;
    let mut parsed = Vec::with_capacity(values.len());
    for raw in values {
        let network: IpNet = raw.parse().map_err(|_| DomainError("INVALID_CIDR"))?;
        if network.trunc() != network || network.to_string() != *raw {
            return Err(DomainError("NONCANONICAL_CIDR"));
        }
        if matches!(
            (network, family),
            (IpNet::V4(_), Family::Ipv6) | (IpNet::V6(_), Family::Ipv4)
        ) {
            return Err(DomainError("FAMILY_MISMATCH"));
        }
        if let IpNet::V6(v6) = network {
            if v6.prefix_len() >= 96 && v6.network().to_ipv4_mapped().is_some() {
                return Err(DomainError("IPV4_MAPPED_IPV6"));
            }
        }
        parsed.push(network);
    }
    parsed.sort_by_key(net_key);
    if parsed
        .windows(2)
        .any(|p| p[0].contains(&p[1].network()) || p[1].contains(&p[0].network()))
    {
        return Err(DomainError("OVERLAPPING_CIDR_LIST"));
    }
    Ok(parsed)
}

fn net_key(n: &IpNet) -> (u128, u8) {
    let address = match n.network() {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    };
    (address, n.prefix_len())
}

impl Scope {
    pub fn validate(&self) -> Result<()> {
        for ids in [&self.source_asset_ids, &self.destination_asset_ids] {
            unique_strings(ids, 1, 256)?;
            for id in ids {
                validate_uuid(id)?;
            }
        }
        networks(&self.source_cidrs, self.family)?;
        networks(&self.destination_cidrs, self.family)?;
        self.transport.validate(self.family)?;
        for interfaces in [&self.ingress_interfaces, &self.egress_interfaces] {
            unique_strings(interfaces, 0, 32)?;
            for interface in interfaces {
                if interface.is_empty()
                    || interface.len() > 15
                    || !interface
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
                {
                    return Err(DomainError("INVALID_INTERFACE"));
                }
            }
        }
        let i = !self.ingress_interfaces.is_empty();
        let o = !self.egress_interfaces.is_empty();
        if !matches!(
            (self.direction, i, o),
            (Direction::Input, true, false)
                | (Direction::Output, false, true)
                | (Direction::Forward, true, true)
        ) {
            return Err(DomainError("INTERFACE_DIRECTION"));
        }
        Ok(())
    }
    /// Bind aliases to a current capability snapshot. Syntax validity alone
    /// never establishes that an interface exists on the selected target.
    pub fn validate_interfaces(&self, known: &[String]) -> Result<()> {
        self.validate()?;
        if self
            .ingress_interfaces
            .iter()
            .chain(&self.egress_interfaces)
            .any(|i| !known.contains(i))
        {
            return Err(DomainError("UNKNOWN_INTERFACE"));
        }
        Ok(())
    }
    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        let mut result = self.clone();
        result.source_asset_ids.sort();
        result.destination_asset_ids.sort();
        result.ingress_interfaces.sort();
        result.egress_interfaces.sort();
        result.source_cidrs = networks(&self.source_cidrs, self.family)?
            .iter()
            .map(ToString::to_string)
            .collect();
        result.destination_cidrs = networks(&self.destination_cidrs, self.family)?
            .iter()
            .map(ToString::to_string)
            .collect();
        result.transport = self.transport.normalized();
        Ok(result)
    }
    pub fn is_subset_of(&self, other: &Self) -> Result<bool> {
        self.validate()?;
        other.validate()?;
        if self.family != other.family
            || self.direction != other.direction
            || self.transport.protocol() != other.transport.protocol()
        {
            return Ok(false);
        }
        for (a, b) in [
            (&self.source_asset_ids, &other.source_asset_ids),
            (&self.destination_asset_ids, &other.destination_asset_ids),
            (&self.ingress_interfaces, &other.ingress_interfaces),
            (&self.egress_interfaces, &other.egress_interfaces),
        ] {
            if a.iter().any(|v| !b.contains(v)) {
                return Ok(false);
            }
        }
        for (a, b) in [
            (&self.source_cidrs, &other.source_cidrs),
            (&self.destination_cidrs, &other.destination_cidrs),
        ] {
            let outer = networks(b, self.family)?;
            if networks(a, self.family)?
                .iter()
                .any(|n| !network_covered(n, &outer))
            {
                return Ok(false);
            }
        }
        match (self.transport.ports(), other.transport.ports()) {
            (Some(a), Some(b)) => Ok(a.iter().all(|p| ports_covered(p, b))),
            _ => Ok(self.transport == other.transport),
        }
    }
    /// Exact packet-space intersection. Asset catalogue labels do not make two
    /// overlapping CIDR scopes disjoint; labels are unioned as provenance.
    pub fn intersection(&self, other: &Self) -> Result<Option<Self>> {
        self.validate()?;
        other.validate()?;
        if self.family != other.family || self.direction != other.direction {
            return Ok(None);
        }
        let Some(transport) = self.transport.intersection(&other.transport) else {
            return Ok(None);
        };
        let source_cidrs =
            intersect_networks(&self.source_cidrs, &other.source_cidrs, self.family)?;
        let destination_cidrs = intersect_networks(
            &self.destination_cidrs,
            &other.destination_cidrs,
            self.family,
        )?;
        let ingress_interfaces =
            intersect_strings(&self.ingress_interfaces, &other.ingress_interfaces);
        let egress_interfaces =
            intersect_strings(&self.egress_interfaces, &other.egress_interfaces);
        if source_cidrs.is_empty()
            || destination_cidrs.is_empty()
            || (self.direction != Direction::Output && ingress_interfaces.is_empty())
            || (self.direction != Direction::Input && egress_interfaces.is_empty())
        {
            return Ok(None);
        }
        let result = Self {
            family: self.family,
            direction: self.direction,
            transport,
            source_cidrs,
            destination_cidrs,
            ingress_interfaces,
            egress_interfaces,
            source_asset_ids: union_strings(&self.source_asset_ids, &other.source_asset_ids),
            destination_asset_ids: union_strings(
                &self.destination_asset_ids,
                &other.destination_asset_ids,
            ),
        };
        Ok(Some(result.normalized()?))
    }
    pub fn intersects(&self, other: &Self) -> Result<bool> {
        Ok(self.intersection(other)?.is_some())
    }
    fn matches(&self, flow: &Flow) -> bool {
        if self.family != flow.family
            || self.direction != flow.direction
            || self.transport.protocol() != flow.protocol
        {
            return false;
        }
        if !self
            .source_cidrs
            .iter()
            .any(|n| n.parse::<IpNet>().is_ok_and(|n| n.contains(&flow.source)))
            || !self.destination_cidrs.iter().any(|n| {
                n.parse::<IpNet>()
                    .is_ok_and(|n| n.contains(&flow.destination))
            })
        {
            return false;
        }
        if self.direction != Direction::Output
            && !flow
                .ingress_interface
                .as_ref()
                .is_some_and(|i| self.ingress_interfaces.contains(i))
        {
            return false;
        }
        if self.direction != Direction::Input
            && !flow
                .egress_interface
                .as_ref()
                .is_some_and(|i| self.egress_interfaces.contains(i))
        {
            return false;
        }
        match &self.transport {
            Transport::Tcp { destination_ports } | Transport::Udp { destination_ports } => {
                flow.destination_port.is_some_and(|port| {
                    destination_ports
                        .iter()
                        .any(|p| p.start <= port && port <= p.end)
                })
            }
            Transport::Icmp { icmp_type, code } | Transport::Icmpv6 { icmp_type, code } => {
                flow.icmp_type == Some(*icmp_type) && flow.icmp_code == Some(*code)
            }
        }
    }
}

fn network_covered(n: &IpNet, outer: &[IpNet]) -> bool {
    // Adjacent narrower networks may together cover a wider requested network.
    let start = net_key(n).0;
    let end = match n.broadcast() {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    };
    let mut next = start;
    for b in outer {
        let first = net_key(b).0;
        let last = match b.broadcast() {
            IpAddr::V4(a) => u32::from(a) as u128,
            IpAddr::V6(a) => u128::from(a),
        };
        if last < next {
            continue;
        }
        if first > next {
            return false;
        }
        if last >= end {
            return true;
        }
        next = last + 1;
    }
    false
}

fn ports_covered(p: &PortRange, outer: &[PortRange]) -> bool {
    let mut sorted = outer.to_vec();
    sorted.sort();
    let mut next = u32::from(p.start);
    for b in sorted {
        if u32::from(b.end) < next {
            continue;
        }
        if u32::from(b.start) > next {
            return false;
        }
        if b.end >= p.end {
            return true;
        }
        next = u32::from(b.end) + 1;
    }
    false
}

fn intersect_strings(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|s| b.contains(s)).cloned().collect()
}
fn union_strings(a: &[String], b: &[String]) -> Vec<String> {
    a.iter()
        .chain(b)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn intersect_networks(a: &[String], b: &[String], family: Family) -> Result<Vec<String>> {
    let a = networks(a, family)?;
    let b = networks(b, family)?;
    let mut out = Vec::new();
    for x in a {
        for y in &b {
            if x.prefix_len() <= y.prefix_len() && x.contains(&y.network()) {
                out.push(y.to_string());
            } else if y.prefix_len() <= x.prefix_len() && y.contains(&x.network()) {
                out.push(x.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Lifetime {
    Lease {
        not_before: String,
        expires_at: String,
    },
    Review {
        not_before: String,
        review_at: String,
    },
}
impl Lifetime {
    pub fn not_before(&self) -> &str {
        match self {
            Self::Lease { not_before, .. } | Self::Review { not_before, .. } => not_before,
        }
    }
    pub fn expires_at(&self) -> Option<&str> {
        match self {
            Self::Lease { expires_at, .. } => Some(expires_at),
            Self::Review { .. } => None,
        }
    }
    pub fn active_at(&self, now: i64) -> Result<bool> {
        Ok(timestamp(self.not_before())? <= now
            && match self {
                Self::Lease { expires_at, .. } => now < timestamp(expires_at)?,
                Self::Review { .. } => true,
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogMode {
    None,
    NewFlow,
    Sampled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: String,
    pub policy_id: String,
    pub policy_revision: u32,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub owner_id: String,
    pub reason: String,
    pub scope: Scope,
    pub log_mode: LogMode,
    pub action: Action,
    pub lifetime: Lifetime,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "f.policy/v1" {
            return Err(DomainError("UNSUPPORTED_SCHEMA"));
        }
        for id in [
            &self.policy_id,
            &self.org_id,
            &self.project_id,
            &self.target_id,
            &self.owner_id,
        ] {
            validate_uuid(id)?;
        }
        if self.policy_revision == 0 || self.policy_revision > i32::MAX as u32 {
            return Err(DomainError("INVALID_REVISION"));
        }
        if self.reason.is_empty() || self.reason.chars().count() > 2000 {
            return Err(DomainError("INVALID_REASON"));
        }
        self.scope.validate()?;
        let start = timestamp(self.lifetime.not_before())?;
        let (end, limit) = match (&self.action, &self.lifetime) {
            (Action::Allow, Lifetime::Lease { expires_at, .. }) => {
                (timestamp(expires_at)?, MAX_ALLOW_SECONDS)
            }
            (Action::Deny, Lifetime::Review { review_at, .. }) => {
                (timestamp(review_at)?, MAX_REVIEW_SECONDS)
            }
            _ => return Err(DomainError("ACTION_LIFETIME_MISMATCH")),
        };
        if end <= start || end - start > limit {
            return Err(DomainError("LIFETIME_LIMIT"));
        }
        Ok(())
    }
    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        let mut result = self.clone();
        result.reason = self.reason.nfc().collect();
        result.scope = self.scope.normalized()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub family: Family,
    pub direction: Direction,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub destination_port: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub ingress_interface: Option<String>,
    pub egress_interface: Option<String>,
}

impl Flow {
    pub fn validate(&self) -> Result<()> {
        for id in [&self.org_id, &self.project_id, &self.target_id] {
            validate_uuid(id)?;
        }
        for address in [self.source, self.destination] {
            if matches!(
                (address, self.family),
                (IpAddr::V4(_), Family::Ipv6) | (IpAddr::V6(_), Family::Ipv4)
            ) {
                return Err(DomainError("FAMILY_MISMATCH"));
            }
            if matches!(address,IpAddr::V6(a) if a.to_ipv4_mapped().is_some()) {
                return Err(DomainError("IPV4_MAPPED_IPV6"));
            }
        }
        match self.protocol {
            Protocol::Tcp | Protocol::Udp
                if self.destination_port.is_some_and(|p| p > 0)
                    && self.icmp_type.is_none()
                    && self.icmp_code.is_none() => {}
            Protocol::Icmp
                if self.family == Family::Ipv4
                    && self.destination_port.is_none()
                    && self.icmp_type.is_some()
                    && self.icmp_code.is_some() => {}
            Protocol::Icmpv6
                if self.family == Family::Ipv6
                    && self.destination_port.is_none()
                    && self.icmp_type.is_some()
                    && self.icmp_code.is_some() => {}
            _ => return Err(DomainError("INVALID_FLOW_TRANSPORT")),
        }
        let i = self.ingress_interface.is_some();
        let o = self.egress_interface.is_some();
        if !matches!(
            (self.direction, i, o),
            (Direction::Input, true, false)
                | (Direction::Output, false, true)
                | (Direction::Forward, true, true)
        ) {
            return Err(DomainError("INTERFACE_DIRECTION"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    pub policy_id: String,
    pub policy_revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", content = "evidence", rename_all = "snake_case")]
pub enum Decision {
    Allow(Vec<PolicyRevision>),
    Deny(Vec<PolicyRevision>),
    DefaultDrop,
    Invalid(String),
}

/// Evaluate business traffic only. Protected management baseline B is a
/// separately verified object and cannot be supplied as an unsigned bypass.
pub fn evaluate(policies: &[Policy], flow: &Flow, now: i64) -> Decision {
    if let Err(e) = flow.validate() {
        return Decision::Invalid(e.to_string());
    }
    let mut identities = BTreeSet::new();
    let mut allows = Vec::new();
    let mut denies = Vec::new();
    for p in policies {
        if let Err(e) = p.validate() {
            return Decision::Invalid(e.to_string());
        }
        if !identities.insert((&p.org_id, &p.project_id, &p.target_id, &p.policy_id)) {
            return Decision::Invalid("DUPLICATE_POLICY_ID".into());
        }
        if p.org_id != flow.org_id
            || p.project_id != flow.project_id
            || p.target_id != flow.target_id
        {
            continue;
        }
        if !p.lifetime.active_at(now).unwrap_or(false) || !p.scope.matches(flow) {
            continue;
        }
        let revision = PolicyRevision {
            policy_id: p.policy_id.clone(),
            policy_revision: p.policy_revision,
        };
        match p.action {
            Action::Allow => allows.push(revision),
            Action::Deny => denies.push(revision),
        }
    }
    allows.sort();
    denies.sort();
    if !denies.is_empty() {
        Decision::Deny(denies)
    } else if !allows.is_empty() {
        Decision::Allow(allows)
    } else {
        Decision::DefaultDrop
    }
}
