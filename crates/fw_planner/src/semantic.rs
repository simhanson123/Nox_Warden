//! Exact finite partition of the pure business-traffic predicate. Each policy is
//! constant within a cell delimited by CIDR, port, interface and lifetime bounds.
//! Management baseline B must be unchanged and is not supplied as unsigned data.
use crate::{PlanError, Relation, Result, StateIr, hash};
use fw_domain::{Decision, Direction, Family, Flow, Policy, Protocol, evaluate, timestamp};
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const DEFAULT_MAX_CELLS: usize = 4096;
#[derive(Debug, Clone, Serialize)]
pub struct SemanticDiff {
    pub relation: Relation,
    pub complete: bool,
    pub evaluated_cells: usize,
    pub newly_allowed_region_hash: String,
    pub removed_region_hash: String,
    pub reason: Option<String>,
}
#[derive(Debug, Serialize)]
struct RegionCell {
    family: Family,
    direction: Direction,
    protocol: Protocol,
    source_start: String,
    source_end: String,
    destination_start: String,
    destination_end: String,
    port_start: u16,
    port_end: u16,
    ingress_interface: Option<String>,
    egress_interface: Option<String>,
    not_before: i64,
    expires_at: Option<i64>,
}
fn unknown(reason: &str, evaluated: usize) -> Result<SemanticDiff> {
    Ok(SemanticDiff {
        relation: Relation::Unknown,
        complete: false,
        evaluated_cells: evaluated,
        newly_allowed_region_hash: hash(&Vec::<RegionCell>::new())?,
        removed_region_hash: hash(&Vec::<RegionCell>::new())?,
        reason: Some(reason.into()),
    })
}
fn numeric(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v) => u32::from(v) as u128,
        IpAddr::V6(v) => u128::from(v),
    }
}
fn ip(value: u128, family: Family) -> IpAddr {
    match family {
        Family::Ipv4 => IpAddr::V4(Ipv4Addr::from(value as u32)),
        Family::Ipv6 => IpAddr::V6(Ipv6Addr::from(value)),
    }
}
fn address_cells(policies: &[&Policy], family: Family, source: bool) -> Result<Vec<(u128, u128)>> {
    let max = if family == Family::Ipv4 {
        u32::MAX as u128
    } else {
        u128::MAX
    };
    let mut boundaries = BTreeSet::from([0u128]);
    for p in policies {
        for raw in if source {
            &p.scope.source_cidrs
        } else {
            &p.scope.destination_cidrs
        } {
            let n: IpNet = raw.parse().map_err(|_| PlanError("invalid CIDR"))?;
            boundaries.insert(numeric(n.network()));
            let end = numeric(n.broadcast());
            if end < max {
                boundaries.insert(end + 1);
            }
        }
    }
    // IPv4-mapped IPv6 addresses are not part of the accepted native flow domain.
    let mapped_start = 0xffffu128 << 32;
    let mapped_end = mapped_start + (u32::MAX as u128);
    if family == Family::Ipv6 {
        boundaries.insert(mapped_start);
        boundaries.insert(mapped_end + 1);
    }
    let b: Vec<_> = boundaries.into_iter().collect();
    Ok(b.iter()
        .enumerate()
        .filter_map(|(i, &start)| {
            let end = b.get(i + 1).map_or(max, |next| next - 1);
            if family == Family::Ipv6 && start == mapped_start {
                None
            } else {
                Some((start, end))
            }
        })
        .collect())
}
fn ports(policies: &[&Policy]) -> Vec<(u16, u16)> {
    let mut bounds = BTreeSet::from([1u32, 65536]);
    for p in policies {
        for r in p.scope.transport.ports().unwrap_or(&[]) {
            bounds.insert(u32::from(r.start));
            bounds.insert(u32::from(r.end) + 1);
        }
    }
    let b: Vec<_> = bounds.into_iter().collect();
    b.windows(2)
        .map(|w| (w[0] as u16, (w[1] - 1) as u16))
        .collect()
}
fn interfaces(policies: &[&Policy], direction: Direction, ingress: bool) -> Vec<Option<String>> {
    if (ingress && direction == Direction::Output) || (!ingress && direction == Direction::Input) {
        return vec![None];
    }
    policies
        .iter()
        .flat_map(|p| {
            if ingress {
                &p.scope.ingress_interfaces
            } else {
                &p.scope.egress_interfaces
            }
        })
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Some)
        .collect()
}
fn times(policies: &[&Policy]) -> Result<Vec<(i64, Option<i64>)>> {
    let mut boundaries = BTreeSet::new();
    for p in policies {
        boundaries.insert(timestamp(p.lifetime.not_before()).map_err(|_| PlanError("lifetime"))?);
        if let Some(expiry) = p.lifetime.expires_at() {
            boundaries.insert(timestamp(expiry).map_err(|_| PlanError("lifetime"))?);
        }
    }
    let b: Vec<_> = boundaries.into_iter().collect();
    Ok(b.iter()
        .enumerate()
        .map(|(i, &start)| (start, b.get(i + 1).copied()))
        .collect())
}

/// Exhaustive for TCP/UDP in the accepted normalized flow domain, including IPv6
/// and explicit interface aliases. ICMP, changed management/registry/capability
/// contexts, >128 policy revisions, or excess cells return incomplete UNKNOWN.
/// `max_cells` is a hard resource bound, never sampling or truncating the proof.
pub fn semantic_diff(before: &StateIr, after: &StateIr, max_cells: usize) -> Result<SemanticDiff> {
    before.validate()?;
    after.validate()?;
    if before.target_id != after.target_id
        || before.platform != after.platform
        || before.profile != after.profile
        || before.management_baseline_hash != after.management_baseline_hash
        || before.source_snapshot_hash != after.source_snapshot_hash
        || before.target_capability_hash != after.target_capability_hash
        || before.tombstone_hashes != after.tombstone_hashes
    {
        return unknown("CONTEXT_CHANGED", 0);
    }
    let all: Vec<_> = before.policies.iter().chain(&after.policies).collect();
    if all.len() > 128 {
        return unknown("POLICY_PROOF_LIMIT", 0);
    }
    if all
        .iter()
        .any(|p| !matches!(p.scope.transport.protocol(), Protocol::Tcp | Protocol::Udp))
    {
        return unknown("UNSUPPORTED_PROTOCOL_PROOF", 0);
    }
    let Some(first) = all.first() else {
        return Ok(SemanticDiff {
            relation: Relation::Equivalent,
            complete: true,
            evaluated_cells: 0,
            newly_allowed_region_hash: hash(&Vec::<RegionCell>::new())?,
            removed_region_hash: hash(&Vec::<RegionCell>::new())?,
            reason: None,
        });
    };
    if all
        .iter()
        .any(|p| p.org_id != first.org_id || p.project_id != first.project_id)
    {
        return unknown("TENANT_CONTEXT_CHANGED", 0);
    }
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut evaluated = 0usize;
    for family in [Family::Ipv4, Family::Ipv6] {
        for direction in [Direction::Input, Direction::Output, Direction::Forward] {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                let group: Vec<_> = all
                    .iter()
                    .copied()
                    .filter(|p| {
                        p.scope.family == family
                            && p.scope.direction == direction
                            && p.scope.transport.protocol() == protocol
                    })
                    .collect();
                if group.is_empty() {
                    continue;
                }
                let sources = address_cells(&group, family, true)?;
                let destinations = address_cells(&group, family, false)?;
                let ports = ports(&group);
                let ingress = interfaces(&group, direction, true);
                let egress = interfaces(&group, direction, false);
                let times = times(&group)?;
                let size = [
                    sources.len(),
                    destinations.len(),
                    ports.len(),
                    ingress.len(),
                    egress.len(),
                    times.len(),
                ]
                .iter()
                .try_fold(1usize, |n, k| n.checked_mul(*k));
                if size
                    .and_then(|n| n.checked_add(evaluated))
                    .is_none_or(|n| n > max_cells.min(32768))
                {
                    return unknown("CELL_PROOF_LIMIT", evaluated);
                }
                for &(source_start, source_end) in &sources {
                    for &(destination_start, destination_end) in &destinations {
                        for &(port_start, port_end) in &ports {
                            for input in &ingress {
                                for output in &egress {
                                    for &(not_before, expires_at) in &times {
                                        let flow = Flow {
                                            org_id: first.org_id.clone(),
                                            project_id: first.project_id.clone(),
                                            target_id: first.target_id.clone(),
                                            family,
                                            direction,
                                            source: ip(source_start, family),
                                            destination: ip(destination_start, family),
                                            protocol,
                                            destination_port: Some(port_start),
                                            icmp_type: None,
                                            icmp_code: None,
                                            ingress_interface: input.clone(),
                                            egress_interface: output.clone(),
                                        };
                                        let old = evaluate(&before.policies, &flow, not_before);
                                        let new = evaluate(&after.policies, &flow, not_before);
                                        if matches!(old, Decision::Invalid(_))
                                            || matches!(new, Decision::Invalid(_))
                                        {
                                            return unknown(
                                                "INVALID_REFERENCE_EVALUATION",
                                                evaluated,
                                            );
                                        }
                                        evaluated += 1;
                                        let old_allowed = matches!(old, Decision::Allow(_));
                                        let new_allowed = matches!(new, Decision::Allow(_));
                                        if old_allowed == new_allowed {
                                            continue;
                                        }
                                        let cell = RegionCell {
                                            family,
                                            direction,
                                            protocol,
                                            source_start: ip(source_start, family).to_string(),
                                            source_end: ip(source_end, family).to_string(),
                                            destination_start: ip(destination_start, family)
                                                .to_string(),
                                            destination_end: ip(destination_end, family)
                                                .to_string(),
                                            port_start,
                                            port_end,
                                            ingress_interface: input.clone(),
                                            egress_interface: output.clone(),
                                            not_before,
                                            expires_at,
                                        };
                                        if new_allowed {
                                            added.push(cell)
                                        } else {
                                            removed.push(cell)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(SemanticDiff {
        relation: match (added.is_empty(), removed.is_empty()) {
            (true, true) => Relation::Equivalent,
            (false, true) => Relation::Expanding,
            (true, false) => Relation::Restricting,
            (false, false) => Relation::Mixed,
        },
        complete: true,
        evaluated_cells: evaluated,
        newly_allowed_region_hash: hash(&added)?,
        removed_region_hash: hash(&removed)?,
        reason: None,
    })
}
