//! Offline PBOM integrity verification. Hashes and signatures establish bytes
//! and signer provenance, never the truth of a device observation. Callers must
//! resolve evidence through an authenticated tenant-scoped store.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, VerifyingKey};
use fw_contracts::canonical_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const PAYLOAD_TYPE: &str = "application/vnd.f.pbom-manifest.v1+json";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("INVALID_PBOM: {0}")]
    Invalid(&'static str),
    #[error("EVIDENCE_NOT_AUTHORIZED")]
    Unauthorized,
    #[error("EVIDENCE_HASH_MISMATCH")]
    HashMismatch,
    #[error("INVALID_SIGNATURE")]
    Signature,
}
type Result<T> = std::result::Result<T, AuditError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Request,
    Policy,
    Plan,
    Approval,
    Delegation,
    Envelope,
    Binding,
    RegistrySnapshot,
    Validation,
    Artifact,
    Grant,
    Installation,
    Receipt,
    Revocation,
    WorkerResult,
    Checkpoint,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    PublicSynthetic,
    Internal,
    Restricted,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub store_id: String,
    pub object_hash: String,
    pub media_type: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node_id: String,
    pub kind: NodeKind,
    pub content_hash: String,
    pub content_ref: EvidenceRef,
    pub recorded_at: String,
    pub classification: Classification,
    pub retention_until: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    DerivedFrom,
    ValidatedBy,
    ApprovedBy,
    AuthorizedBy,
    AppliedAs,
    ObservedBy,
    RevokedBy,
    Supersedes,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from_id: String,
    pub to_id: String,
    pub relation: Relation,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestPayload {
    pub schema_version: String,
    pub manifest_id: String,
    pub org_id: String,
    pub project_id: String,
    pub root_operation_id: String,
    pub created_at: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub previous_checkpoint_hash: Option<String>,
    pub merkle_root: String,
    pub completeness: Completeness,
    pub missing_hashes: Vec<String>,
}
/// Evidence metadata is supplied by a trusted store, not taken from its body.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub org_id: String,
    pub project_id: String,
    pub store_id: String,
    pub media_type: String,
    pub classification: Classification,
    pub bytes: Vec<u8>,
}
pub struct EvidenceAccess<'a> {
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub stores: &'a BTreeSet<String>,
    pub maximum_classification: Classification,
    /// Mandatory lifecycle stages chosen by the verifier for this operation.
    /// Never derive these from a sender's completeness claim.
    pub required_stages: &'a [NodeKind],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    pub verified_objects: usize,
    pub missing_hashes: Vec<String>,
    pub completeness: Completeness,
    pub signature_verified: bool,
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}
fn timestamp(s: &str) -> Result<i64> {
    if s.len() != 20 || !s.ends_with('Z') {
        return Err(AuditError::Invalid("timestamp"));
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.timestamp())
        .map_err(|_| AuditError::Invalid("timestamp"))
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    canonical_bytes(v).map_err(|_| AuditError::Invalid("canonicalization"))
}
fn relation_name(r: &Relation) -> &'static str {
    match r {
        Relation::DerivedFrom => "derived_from",
        Relation::ValidatedBy => "validated_by",
        Relation::ApprovedBy => "approved_by",
        Relation::AuthorizedBy => "authorized_by",
        Relation::AppliedAs => "applied_as",
        Relation::ObservedBy => "observed_by",
        Relation::RevokedBy => "revoked_by",
        Relation::Supersedes => "supersedes",
    }
}
/// Exact F-2.0 tree: sorted nodes, 0x00 leaf prefix, 0x01 internal prefix,
/// and an unpaired last hash promoted unchanged (not duplicated).
pub fn merkle_root(nodes: &[Node]) -> Result<String> {
    if nodes.is_empty() || nodes.len() > 512 {
        return Err(AuditError::Invalid("node_count"));
    }
    let mut sorted = nodes.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    if sorted.windows(2).any(|w| w[0].node_id == w[1].node_id) {
        return Err(AuditError::Invalid("duplicate_node"));
    }
    let mut hashes = sorted
        .into_iter()
        .map(|n| {
            let mut h = Sha256::new();
            h.update([0]);
            h.update(canonical(n)?);
            Ok(<[u8; 32]>::from(h.finalize()))
        })
        .collect::<Result<Vec<_>>>()?;
    while hashes.len() > 1 {
        hashes = hashes
            .chunks(2)
            .map(|c| {
                if c.len() == 1 {
                    c[0]
                } else {
                    let mut h = Sha256::new();
                    h.update([1]);
                    h.update(c[0]);
                    h.update(c[1]);
                    h.finalize().into()
                }
            })
            .collect();
    }
    Ok(format!(
        "sha256:{}",
        hashes[0]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

pub fn verify_graph(
    payload: &ManifestPayload,
    access: &EvidenceAccess<'_>,
    records: &BTreeMap<String, EvidenceRecord>,
) -> Result<IntegrityReport> {
    if payload.org_id != access.org_id || payload.project_id != access.project_id {
        return Err(AuditError::Unauthorized);
    }
    if payload.schema_version != "f.pbom-manifest/v1"
        || ![
            &payload.manifest_id,
            &payload.org_id,
            &payload.project_id,
            &payload.root_operation_id,
        ]
        .iter()
        .all(|s| valid_uuid(s))
    {
        return Err(AuditError::Invalid("manifest_identity"));
    }
    timestamp(&payload.created_at)?;
    if payload.edges.len() > 2048
        || payload.missing_hashes.len() > 128
        || payload
            .previous_checkpoint_hash
            .as_ref()
            .is_some_and(|h| !valid_hash(h))
    {
        return Err(AuditError::Invalid("limits_or_hash"));
    }
    if !payload
        .nodes
        .windows(2)
        .all(|w| w[0].node_id < w[1].node_id)
    {
        return Err(AuditError::Invalid("node_order"));
    }
    let mut edge_keys = BTreeSet::new();
    for edge in &payload.edges {
        if !edge_keys.insert((&edge.from_id, &edge.to_id, relation_name(&edge.relation))) {
            return Err(AuditError::Invalid("duplicate_edge"));
        }
    }
    if !payload.edges.windows(2).all(|w| {
        (&w[0].from_id, &w[0].to_id, relation_name(&w[0].relation))
            < (&w[1].from_id, &w[1].to_id, relation_name(&w[1].relation))
    }) {
        return Err(AuditError::Invalid("edge_order"));
    }
    let ids = payload
        .nodes
        .iter()
        .map(|n| n.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut degrees = ids
        .iter()
        .map(|&id| (id, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &payload.edges {
        if !ids.contains(e.from_id.as_str()) || !ids.contains(e.to_id.as_str()) {
            return Err(AuditError::Invalid("dangling_edge"));
        }
        *degrees
            .get_mut(e.to_id.as_str())
            .ok_or(AuditError::Invalid("edge"))? += 1;
        outgoing.entry(&e.from_id).or_default().push(&e.to_id);
    }
    let mut queue = degrees
        .iter()
        .filter_map(|(&id, &d)| (d == 0).then_some(id))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        for next in outgoing.get(id).into_iter().flatten() {
            let d = degrees.get_mut(next).ok_or(AuditError::Invalid("edge"))?;
            *d -= 1;
            if *d == 0 {
                queue.push_back(next);
            }
        }
    }
    if visited != ids.len() {
        return Err(AuditError::Invalid("cycle"));
    }
    let declared = payload
        .missing_hashes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared.len() != payload.missing_hashes.len() || !declared.iter().all(|h| valid_hash(h)) {
        return Err(AuditError::Invalid("missing_hashes"));
    }
    let mut missing = BTreeSet::new();
    let mut verified = 0;
    for node in &payload.nodes {
        let r = &node.content_ref;
        if !valid_uuid(&node.node_id)
            || !valid_hash(&node.content_hash)
            || r.object_hash != node.content_hash
            || r.size_bytes > 16_777_216
            || !matches!(
                r.media_type.as_str(),
                "application/json" | "application/octet-stream" | "text/plain"
            )
        {
            return Err(AuditError::Invalid("node_metadata"));
        }
        let valid_store = !r.store_id.is_empty()
            && r.store_id.len() <= 64
            && r.store_id.as_bytes()[0].is_ascii_lowercase()
            && r.store_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !valid_store
            || !access.stores.contains(&r.store_id)
            || node.classification > access.maximum_classification
        {
            return Err(AuditError::Unauthorized);
        }
        if timestamp(&node.retention_until)? < timestamp(&node.recorded_at)? {
            return Err(AuditError::Invalid("retention"));
        }
        if let Some(record) = records.get(&node.content_hash) {
            if record.org_id != access.org_id
                || record.project_id != access.project_id
                || record.store_id != r.store_id
                || record.classification != node.classification
            {
                return Err(AuditError::Unauthorized);
            }
            if record.media_type != r.media_type
                || record.bytes.len() as u64 != r.size_bytes
                || hash_bytes(&record.bytes) != node.content_hash
            {
                return Err(AuditError::HashMismatch);
            }
            verified += 1;
        } else {
            missing.insert(node.content_hash.clone());
        }
    }
    if !missing.is_subset(&declared) {
        return Err(AuditError::Invalid("undeclared_missing_evidence"));
    }
    if payload.completeness == Completeness::Complete
        && (!declared.is_empty()
            || access.required_stages.is_empty()
            || !access
                .required_stages
                .iter()
                .all(|kind| payload.nodes.iter().any(|n| &n.kind == kind)))
    {
        return Err(AuditError::Invalid("unproven_completeness"));
    }
    if merkle_root(&payload.nodes)? != payload.merkle_root {
        return Err(AuditError::HashMismatch);
    }
    Ok(IntegrityReport {
        verified_objects: verified,
        missing_hashes: declared.into_iter().collect(),
        completeness: payload.completeness,
        signature_verified: false,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dsse {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<Signature>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub payload: ManifestPayload,
    pub dsse: Dsse,
}
/// Key selection/validity/revocation is a trusted registry's responsibility.
/// Tenant and time binding are still checked here, independently of keyid.
pub struct AuditTrustKey<'a> {
    pub keyid: &'a str,
    pub key: &'a VerifyingKey,
    pub org_id: &'a str,
    pub project_id: &'a str,
    pub valid_from: i64,
    pub valid_until: i64,
    pub revoked: bool,
}
fn pae(payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        PAYLOAD_TYPE.len(),
        PAYLOAD_TYPE,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}
/// Creates an audit signature only. It confers no approval or firewall authority.
/// Call verify_graph first with authenticated evidence and desired requirements.
pub fn sign_manifest(
    payload: ManifestPayload,
    keyid: &str,
    key: &SigningKey,
) -> Result<SignedManifest> {
    if keyid.is_empty() || keyid.len() > 128 {
        return Err(AuditError::Invalid("keyid"));
    }
    let bytes = canonical(&payload)?;
    let sig = key.sign(&pae(&bytes));
    Ok(SignedManifest {
        payload,
        dsse: Dsse {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: STANDARD.encode(bytes),
            signatures: vec![Signature {
                keyid: keyid.to_owned(),
                sig: STANDARD.encode(sig.to_bytes()),
            }],
        },
    })
}
pub fn verify_signed_manifest(
    manifest: &SignedManifest,
    trust: &AuditTrustKey<'_>,
    now: i64,
    access: &EvidenceAccess<'_>,
    records: &BTreeMap<String, EvidenceRecord>,
) -> Result<IntegrityReport> {
    if trust.revoked
        || now < trust.valid_from
        || now >= trust.valid_until
        || trust.org_id != access.org_id
        || trust.project_id != access.project_id
        || manifest.dsse.payload_type != PAYLOAD_TYPE
        || manifest.dsse.signatures.is_empty()
        || manifest.dsse.signatures.len() > 8
    {
        return Err(AuditError::Signature);
    }
    let bytes = canonical(&manifest.payload)?;
    if STANDARD
        .decode(&manifest.dsse.payload)
        .map_err(|_| AuditError::Signature)?
        != bytes
    {
        return Err(AuditError::Signature);
    }
    let mut seen = BTreeSet::new();
    let mut accepted = false;
    for s in &manifest.dsse.signatures {
        if !seen.insert((&s.keyid, &s.sig)) {
            return Err(AuditError::Signature);
        }
        if s.keyid == trust.keyid {
            let raw = STANDARD.decode(&s.sig).map_err(|_| AuditError::Signature)?;
            let sig = EdSignature::from_slice(&raw).map_err(|_| AuditError::Signature)?;
            trust
                .key
                .verify_strict(&pae(&bytes), &sig)
                .map_err(|_| AuditError::Signature)?;
            accepted = true;
        }
    }
    if !accepted {
        return Err(AuditError::Signature);
    }
    let mut report = verify_graph(&manifest.payload, access, records)?;
    report.signature_verified = true;
    Ok(report)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redaction {
    pub json_pointer: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedDerivative {
    pub original_object_hash: String,
    pub content: serde_json::Value,
    pub redactions: Vec<Redaction>,
    pub original_signature_verifiable: bool,
}
/// Redacted bytes are a derivative; original signatures are never reused.
pub fn redact(
    original: &serde_json::Value,
    redactions: Vec<Redaction>,
) -> Result<RedactedDerivative> {
    if redactions.is_empty() || redactions.len() > 256 {
        return Err(AuditError::Invalid("redactions"));
    }
    let original_object_hash = hash_bytes(&canonical(original)?);
    let mut content = original.clone();
    let mut seen = BTreeSet::new();
    for redaction in &redactions {
        if redaction.reason.is_empty()
            || redaction.reason.len() > 256
            || !seen.insert(&redaction.json_pointer)
        {
            return Err(AuditError::Invalid("redaction"));
        }
        let field = content
            .pointer_mut(&redaction.json_pointer)
            .ok_or(AuditError::Invalid("redaction_pointer"))?;
        *field = serde_json::Value::String("[REDACTED]".into());
    }
    Ok(RedactedDerivative {
        original_object_hash,
        content,
        redactions,
        original_signature_verifiable: false,
    })
}
/// Spreadsheet export quotes every field and neutralizes formula prefixes,
/// including leading whitespace that spreadsheet importers may ignore.
pub fn csv_field(input: &str) -> String {
    let trim = input.trim_start();
    let danger = trim.starts_with(['=', '+', '-', '@']) || input.starts_with(['\t', '\r', '\n']);
    let escaped = input.replace('"', "\"\"");
    format!("\"{}{escaped}\"", if danger { "'" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORG: &str = "10000000-0000-4000-8000-000000000001";
    const PROJECT: &str = "10000000-0000-4000-8000-000000000002";
    fn fixture(count: usize) -> (ManifestPayload, BTreeMap<String, EvidenceRecord>) {
        let mut nodes = Vec::new();
        let mut records = BTreeMap::new();
        for i in 1..=count {
            let bytes = format!("{{\"ordinal\":{i}}}").into_bytes();
            let hash = hash_bytes(&bytes);
            records.insert(
                hash.clone(),
                EvidenceRecord {
                    org_id: ORG.into(),
                    project_id: PROJECT.into(),
                    store_id: "local".into(),
                    media_type: "application/json".into(),
                    classification: Classification::Internal,
                    bytes: bytes.clone(),
                },
            );
            nodes.push(Node {
                node_id: format!("20000000-0000-4000-8000-{i:012}"),
                kind: NodeKind::Request,
                content_hash: hash.clone(),
                content_ref: EvidenceRef {
                    store_id: "local".into(),
                    object_hash: hash,
                    media_type: "application/json".into(),
                    size_bytes: bytes.len() as u64,
                },
                recorded_at: "2026-10-30T00:00:00Z".into(),
                classification: Classification::Internal,
                retention_until: "2027-01-28T00:00:00Z".into(),
            });
        }
        let root = merkle_root(&nodes).unwrap();
        (
            ManifestPayload {
                schema_version: "f.pbom-manifest/v1".into(),
                manifest_id: "30000000-0000-4000-8000-000000000001".into(),
                org_id: ORG.into(),
                project_id: PROJECT.into(),
                root_operation_id: "40000000-0000-4000-8000-000000000001".into(),
                created_at: "2026-10-30T00:00:00Z".into(),
                nodes,
                edges: vec![],
                previous_checkpoint_hash: None,
                merkle_root: root,
                completeness: Completeness::Complete,
                missing_hashes: vec![],
            },
            records,
        )
    }
    fn check(p: &ManifestPayload, r: &BTreeMap<String, EvidenceRecord>) -> Result<IntegrityReport> {
        let stores = BTreeSet::from(["local".to_owned()]);
        verify_graph(
            p,
            &EvidenceAccess {
                org_id: ORG,
                project_id: PROJECT,
                stores: &stores,
                maximum_classification: Classification::Internal,
                required_stages: &[NodeKind::Request],
            },
            r,
        )
    }
    #[test]
    fn valid_graph_checks_real_content() {
        let (p, mut r) = fixture(3);
        assert_eq!(check(&p, &r).unwrap().verified_objects, 3);
        r.get_mut(&p.nodes[1].content_hash).unwrap().bytes.push(0);
        assert_eq!(check(&p, &r), Err(AuditError::HashMismatch));
    }
    #[test]
    fn merkle_odd_node_is_promoted_not_duplicated() {
        let (p, _) = fixture(3);
        let leaves = p
            .nodes
            .iter()
            .map(|n| {
                let mut h = Sha256::new();
                h.update([0]);
                h.update(canonical(n).unwrap());
                <[u8; 32]>::from(h.finalize())
            })
            .collect::<Vec<_>>();
        let mut left = Sha256::new();
        left.update([1]);
        left.update(leaves[0]);
        left.update(leaves[1]);
        let mut root = Sha256::new();
        root.update([1]);
        root.update(left.finalize());
        root.update(leaves[2]);
        assert_eq!(p.merkle_root, format!("sha256:{:x}", root.finalize()));
        let mut reversed = p.nodes.clone();
        reversed.reverse();
        assert_eq!(merkle_root(&reversed).unwrap(), p.merkle_root);
    }
    #[test]
    fn cycle_dangling_and_duplicate_nodes_rejected() {
        let (mut p, r) = fixture(2);
        p.edges = vec![
            Edge {
                from_id: p.nodes[0].node_id.clone(),
                to_id: p.nodes[1].node_id.clone(),
                relation: Relation::DerivedFrom,
            },
            Edge {
                from_id: p.nodes[1].node_id.clone(),
                to_id: p.nodes[0].node_id.clone(),
                relation: Relation::DerivedFrom,
            },
        ];
        assert_eq!(check(&p, &r), Err(AuditError::Invalid("cycle")));
        p.edges.truncate(1);
        p.edges[0].to_id = "missing".into();
        assert_eq!(check(&p, &r), Err(AuditError::Invalid("dangling_edge")));
        p.edges.clear();
        p.nodes[1].node_id = p.nodes[0].node_id.clone();
        assert!(check(&p, &r).is_err());
    }
    #[test]
    fn tenant_store_and_classification_cannot_be_asserted_by_sender() {
        let (mut p, mut r) = fixture(1);
        r.get_mut(&p.nodes[0].content_hash).unwrap().org_id = PROJECT.into();
        assert_eq!(check(&p, &r), Err(AuditError::Unauthorized));
        r.get_mut(&p.nodes[0].content_hash).unwrap().org_id = ORG.into();
        p.nodes[0].content_ref.store_id = "https://evil.test".into();
        assert_eq!(check(&p, &r), Err(AuditError::Unauthorized));
        p.nodes[0].content_ref.store_id = "local".into();
        p.nodes[0].classification = Classification::Restricted;
        assert_eq!(check(&p, &r), Err(AuditError::Unauthorized));
    }
    #[test]
    fn completeness_requires_available_evidence_and_independent_stages() {
        let (mut p, mut r) = fixture(1);
        r.clear();
        assert!(check(&p, &r).is_err());
        p.missing_hashes.push(p.nodes[0].content_hash.clone());
        assert_eq!(
            check(&p, &r),
            Err(AuditError::Invalid("unproven_completeness"))
        );
        p.completeness = Completeness::Partial;
        assert_eq!(check(&p, &r).unwrap().verified_objects, 0);
    }
    #[test]
    fn dsse_binds_payload_edges_tenant_and_current_key() {
        let (p, r) = fixture(2);
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key();
        let mut m = sign_manifest(p, "audit-1", &key).unwrap();
        let stores = BTreeSet::from(["local".into()]);
        let access = EvidenceAccess {
            org_id: ORG,
            project_id: PROJECT,
            stores: &stores,
            maximum_classification: Classification::Internal,
            required_stages: &[NodeKind::Request],
        };
        let mut trust = AuditTrustKey {
            keyid: "audit-1",
            key: &public,
            org_id: ORG,
            project_id: PROJECT,
            valid_from: 1,
            valid_until: 100,
            revoked: false,
        };
        assert!(
            verify_signed_manifest(&m, &trust, 50, &access, &r)
                .unwrap()
                .signature_verified
        );
        assert_eq!(
            verify_signed_manifest(&m, &trust, 100, &access, &r),
            Err(AuditError::Signature)
        );
        trust.revoked = true;
        assert_eq!(
            verify_signed_manifest(&m, &trust, 50, &access, &r),
            Err(AuditError::Signature)
        );
        trust.revoked = false;
        m.payload.edges.push(Edge {
            from_id: m.payload.nodes[0].node_id.clone(),
            to_id: m.payload.nodes[1].node_id.clone(),
            relation: Relation::ApprovedBy,
        });
        assert_eq!(
            verify_signed_manifest(&m, &trust, 50, &access, &r),
            Err(AuditError::Signature)
        );
    }
    #[test]
    fn redaction_is_derivative_never_original_signature_pass() {
        let source =
            serde_json::json!({"subject":{"email":"sensitive@example.test"},"status":"unknown"});
        let result = redact(
            &source,
            vec![Redaction {
                json_pointer: "/subject/email".into(),
                reason: "scope".into(),
            }],
        )
        .unwrap();
        assert!(!result.original_signature_verifiable);
        assert_eq!(source["subject"]["email"], "sensitive@example.test");
        assert_eq!(result.content["subject"]["email"], "[REDACTED]");
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("sensitive@example.test")
        );
    }
    #[test]
    fn csv_does_not_execute_formulas() {
        assert_eq!(csv_field("=1+2"), "\"'=1+2\"");
        assert_eq!(csv_field(" \t@evil"), "\"' \t@evil\"");
        assert_eq!(csv_field("a,\"b"), "\"a,\"\"b\"");
    }
}
