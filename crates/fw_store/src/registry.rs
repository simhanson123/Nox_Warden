//! Immutable manual asset/service catalog. Catalog claims never establish workload bindings.
use super::*;
use fw_domain::Transport;
use ipnet::IpNet;
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMutation {
    pub value: Value,
    pub replayed: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssetWrite {
    definition: AssetDefinition,
    state: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssetDefinition {
    name: String,
    asset_kind: String,
    owner_id: String,
    addresses: Vec<AssetAddress>,
    criticality: String,
    isolation: String,
    provenance: String,
    source_evidence: Value,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssetAddress {
    family: String,
    cidr: String,
    interface: Value,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceCreate {
    service_id: String,
    definition: ServiceDefinition,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceWrite {
    definition: ServiceDefinition,
    state: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceDefinition {
    name: String,
    owner_id: String,
    destination_asset_ids: Vec<String>,
    target_ids: Vec<String>,
    transport: Transport,
    description: String,
    criticality: String,
}
#[derive(Clone, Copy)]
enum Kind {
    Asset,
    Service,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Asset => "asset",
            Self::Service => "service",
        }
    }
    fn table(self) -> &'static str {
        match self {
            Self::Asset => "assets",
            Self::Service => "services",
        }
    }
    fn revisions(self) -> &'static str {
        match self {
            Self::Asset => "asset_revisions",
            Self::Service => "service_revisions",
        }
    }
    fn id(self) -> &'static str {
        match self {
            Self::Asset => "asset_id",
            Self::Service => "service_id",
        }
    }
    fn validate_id(self, id: &str) -> Result<()> {
        match self {
            Self::Asset => valid_uuid(id),
            Self::Service => service_id(id),
        }
    }
}

impl Store {
    pub fn create_asset(
        &self,
        t: &Tenant,
        principal: &str,
        body: &Value,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        let mut body: AssetWrite = serde_json::from_value(body.clone())?;
        body.validate()?;
        self.write_registry(
            t,
            principal,
            Kind::Asset,
            None,
            &serde_json::to_value(body)?,
            None,
            key,
            now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn revise_asset(
        &self,
        t: &Tenant,
        principal: &str,
        id: &str,
        body: &Value,
        expected_revision: i32,
        expected_hash: &str,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        let mut body: AssetWrite = serde_json::from_value(body.clone())?;
        body.validate()?;
        self.write_registry(
            t,
            principal,
            Kind::Asset,
            Some(id),
            &serde_json::to_value(body)?,
            Some((expected_revision, expected_hash)),
            key,
            now,
        )
    }
    pub fn create_service(
        &self,
        t: &Tenant,
        principal: &str,
        body: &Value,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        let mut body: ServiceCreate = serde_json::from_value(body.clone())?;
        service_id(&body.service_id)?;
        body.definition.validate()?;
        self.write_registry(
            t,
            principal,
            Kind::Service,
            Some(&body.service_id),
            &serde_json::to_value(&body)?,
            None,
            key,
            now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn revise_service(
        &self,
        t: &Tenant,
        principal: &str,
        id: &str,
        body: &Value,
        expected_revision: i32,
        expected_hash: &str,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        let mut body: ServiceWrite = serde_json::from_value(body.clone())?;
        valid_state(&body.state)?;
        body.definition.validate()?;
        self.write_registry(
            t,
            principal,
            Kind::Service,
            Some(id),
            &serde_json::to_value(body)?,
            Some((expected_revision, expected_hash)),
            key,
            now,
        )
    }
    pub fn get_asset(&self, t: &Tenant, id: &str) -> Result<Value> {
        let c = self.connection()?;
        read_registry(&c, t, Kind::Asset, id, None)
    }
    pub fn get_service(&self, t: &Tenant, id: &str) -> Result<Value> {
        let c = self.connection()?;
        read_registry(&c, t, Kind::Service, id, None)
    }
    pub fn get_asset_revision(&self, t: &Tenant, id: &str, revision: i32) -> Result<Value> {
        let c = self.connection()?;
        read_registry(&c, t, Kind::Asset, id, Some(revision))
    }
    pub fn get_service_revision(&self, t: &Tenant, id: &str, revision: i32) -> Result<Value> {
        let c = self.connection()?;
        read_registry(&c, t, Kind::Service, id, Some(revision))
    }
    pub fn list_assets(&self, t: &Tenant, limit: usize) -> Result<Vec<Value>> {
        let c = self.connection()?;
        list_registry(&c, t, Kind::Asset, limit)
    }
    pub fn list_services(&self, t: &Tenant, limit: usize) -> Result<Vec<Value>> {
        let c = self.connection()?;
        list_registry(&c, t, Kind::Service, limit)
    }
    pub fn count_assets(&self, t: &Tenant) -> Result<u64> {
        let c = self.connection()?;
        count_registry(&c, t, Kind::Asset)
    }
    pub fn count_services(&self, t: &Tenant) -> Result<u64> {
        let c = self.connection()?;
        count_registry(&c, t, Kind::Service)
    }
    pub fn security_revision(&self, t: &Tenant) -> Result<i32> {
        self.connection()?
            .query_row(
                "SELECT security_revision FROM projects WHERE org_id=?1 AND project_id=?2",
                params![t.org_id, t.project_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_registry(
        &self,
        t: &Tenant,
        principal: &str,
        kind: Kind,
        id: Option<&str>,
        body: &Value,
        expected: Option<(i32, &str)>,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        valid_uuid(principal)?;
        valid_uuid(key)?;
        valid_time(now)?;
        if let Some(id) = id {
            kind.validate_id(id)?;
        }
        if let Some((revision, hash)) = expected {
            if revision < 1 {
                return Err(StoreError::InvalidInput("revision"));
            }
            decode_hash(hash)?;
        }
        let body_bytes = canonical_bytes(body)?;
        if body_bytes.len() > 65536 {
            return Err(StoreError::InvalidInput("body exceeds 64 KiB"));
        }
        let body_hash = sha256(&body_bytes);
        let route = if expected.is_some() {
            format!(
                "/api/v1/{}/{}/revisions",
                kind.table(),
                id.ok_or(StoreError::InvalidInput("resource ID"))?
            )
        } else {
            format!("/api/v1/{}", kind.table())
        };
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_principal(&tx, t, principal)?;
        let prior:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT body_hash,response_bytes FROM registry_idempotency WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND method='POST' AND route=?4 AND key=?5",params![t.org_id,t.project_id,principal,route,key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((old_hash, response)) = prior {
            if old_hash != body_hash {
                return Err(StoreError::IdempotencyConflict);
            }
            let value: Value = serde_json::from_slice(&response)?;
            let replay_id = value[kind.id()]
                .as_str()
                .ok_or(StoreError::Integrity("idempotency resource ID"))?;
            let replay_revision = value["revision"]
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .ok_or(StoreError::Integrity("idempotency revision"))?;
            if read_registry(&tx, t, kind, replay_id, Some(replay_revision))? != value {
                return Err(StoreError::Integrity("idempotency response mismatch"));
            }
            return Ok(RegistryMutation {
                value,
                replayed: true,
            });
        }
        let resource_id = id
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let definition = &body["definition"];
        let owner = definition["owner_id"]
            .as_str()
            .ok_or(StoreError::InvalidInput("owner"))?;
        active_principal(&tx, t, owner)?;
        let state = body
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("active");
        valid_state(state)?;
        let old = match read_registry(&tx, t, kind, &resource_id, None) {
            Ok(value) => Some(value),
            Err(StoreError::NotFound) => None,
            Err(error) => return Err(error),
        };
        let (revision, previous_hash) = match (expected, old) {
            (None, None) => (1, None),
            (None, Some(_)) => return Err(StoreError::Conflict("RESOURCE_EXISTS")),
            (Some(_), None) => return Err(StoreError::NotFound),
            (Some((expected_revision, expected_hash)), Some(old)) => {
                if old["state"] == "retired" {
                    return Err(StoreError::Retired);
                }
                if old["revision"].as_i64() != Some(expected_revision as i64)
                    || old["content_hash"] != expected_hash
                {
                    return Err(StoreError::PreconditionFailed);
                }
                (
                    expected_revision
                        .checked_add(1)
                        .ok_or(StoreError::PreconditionFailed)?,
                    Some(expected_hash.to_owned()),
                )
            }
        };
        let name = definition["name"]
            .as_str()
            .ok_or(StoreError::InvalidInput("name"))?;
        let duplicate:bool=tx.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {} WHERE org_id=?1 AND project_id=?2 AND name=?3 AND {}<>?4)",kind.table(),kind.id()),params![t.org_id,t.project_id,name,resource_id],|r|r.get(0))?;
        if duplicate {
            return Err(StoreError::Conflict("NAME_EXISTS"));
        }
        match kind {
            Kind::Asset => {}
            Kind::Service => validate_service_refs(&tx, t, definition, state)?,
        }
        let mut revision_value = json!({"schema_version":format!("f.{}/v1",kind.name()),"org_id":t.org_id,"project_id":t.project_id,"revision":revision,"definition":definition,"created_at":timestamp(now)?,"created_by":principal,"previous_revision_hash":previous_hash,"state":state});
        revision_value[kind.id()] = Value::String(resource_id.clone());
        let content_bytes = canonical_bytes(&revision_value)?;
        let hash = sha256(&content_bytes);
        let content_hash = hash_bytes(&content_bytes);
        if content_bytes.len() > 65536 {
            return Err(StoreError::InvalidInput("registry revision exceeds 64 KiB"));
        }
        let previous_bytes = previous_hash.as_deref().map(decode_hash).transpose()?;
        if revision == 1 {
            tx.execute(
                &format!("INSERT INTO {} VALUES(?1,?2,?3,?4,?5,?6)", kind.table()),
                params![t.org_id, t.project_id, resource_id, revision, state, name],
            )?;
        } else {
            let changed=tx.execute(&format!("UPDATE {} SET current_revision=?4,state=?5,name=?6 WHERE org_id=?1 AND project_id=?2 AND {}=?3 AND current_revision=?7",kind.table(),kind.id()),params![t.org_id,t.project_id,resource_id,revision,state,name,revision-1])?;
            if changed != 1 {
                return Err(StoreError::PreconditionFailed);
            }
        }
        match kind {
            Kind::Asset => {
                tx.execute("INSERT INTO asset_revisions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'manual',?11,?12,?13,?14)",params![t.org_id,t.project_id,resource_id,revision,hash.as_slice(),previous_bytes,owner,definition["asset_kind"].as_str(),definition["criticality"].as_str(),definition["isolation"].as_str(),principal,now,state,content_bytes])?;
                for address in definition["addresses"]
                    .as_array()
                    .ok_or(StoreError::InvalidInput("addresses"))?
                {
                    let cidr = address["cidr"]
                        .as_str()
                        .ok_or(StoreError::InvalidInput("CIDR"))?
                        .parse::<IpNet>()
                        .map_err(|_| StoreError::InvalidInput("CIDR"))?;
                    let (bytes, prefix) = network_bytes(cidr);
                    let label = address["interface"].as_str();
                    tx.execute(
                        "INSERT INTO asset_addresses VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        params![
                            t.org_id,
                            t.project_id,
                            resource_id,
                            revision,
                            address["family"].as_str(),
                            bytes,
                            prefix,
                            label.unwrap_or(""),
                            label
                        ],
                    )?;
                }
            }
            Kind::Service => {
                tx.execute(
                    "INSERT INTO service_revisions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![
                        t.org_id,
                        t.project_id,
                        resource_id,
                        revision,
                        hash.as_slice(),
                        previous_bytes,
                        owner,
                        canonical_bytes(&definition["transport"])?,
                        principal,
                        now,
                        state,
                        content_bytes
                    ],
                )?;
                for asset in strings(&definition["destination_asset_ids"])? {
                    tx.execute(
                        "INSERT INTO service_destinations VALUES(?1,?2,?3,?4,?5)",
                        params![t.org_id, t.project_id, resource_id, revision, asset],
                    )?;
                }
                for target in strings(&definition["target_ids"])? {
                    tx.execute(
                        "INSERT INTO service_targets VALUES(?1,?2,?3,?4,?5)",
                        params![t.org_id, t.project_id, resource_id, revision, target],
                    )?;
                }
                let transport: Transport = serde_json::from_value(definition["transport"].clone())?;
                match transport {
                    Transport::Tcp { destination_ports } | Transport::Udp { destination_ports } => {
                        for port in destination_ports {
                            tx.execute(
                                "INSERT INTO service_ports VALUES(?1,?2,?3,?4,?5,?6,?7)",
                                params![
                                    t.org_id,
                                    t.project_id,
                                    resource_id,
                                    revision,
                                    definition["transport"]["protocol"].as_str(),
                                    port.start,
                                    port.end
                                ],
                            )?;
                        }
                    }
                    Transport::Icmp { icmp_type, code } | Transport::Icmpv6 { icmp_type, code } => {
                        tx.execute(
                            "INSERT INTO service_icmp VALUES(?1,?2,?3,?4,?5,?6,?7)",
                            params![
                                t.org_id,
                                t.project_id,
                                resource_id,
                                revision,
                                definition["transport"]["protocol"].as_str(),
                                icmp_type,
                                code
                            ],
                        )?;
                    }
                }
            }
        }
        let changed=tx.execute("UPDATE projects SET security_revision=security_revision+1 WHERE org_id=?1 AND project_id=?2 AND security_revision<2147483647",params![t.org_id,t.project_id])?;
        if changed != 1 {
            return Err(StoreError::PreconditionFailed);
        }
        revision_value["content_hash"] = Value::String(content_hash.clone());
        let response = canonical_bytes(&revision_value)?;
        let expires_at = now
            .checked_add(30 * 86400)
            .ok_or(StoreError::InvalidInput("expiry overflow"))?;
        valid_time(expires_at)?;
        tx.execute("INSERT INTO registry_idempotency VALUES(?1,?2,?3,'POST',?4,?5,?6,?7,?8,?9,201,?10,?11,?12)",params![t.org_id,t.project_id,principal,route,key,body_hash.as_slice(),kind.name(),resource_id,revision,response,now,expires_at])?;
        enqueue(
            &tx,
            t,
            kind.name(),
            &resource_id,
            revision,
            "registry.revised",
            &json!({"resource_kind":kind.name(),"resource_id":resource_id,"revision":revision,"content_hash":content_hash,"state":state,"authority":"manual_catalog_only"}),
            now,
        )?;
        let audit_id = match kind {
            Kind::Asset => Some(resource_id.as_str()),
            Kind::Service => None,
        };
        append_audit_with_evidence(
            &tx,
            t,
            Some(principal),
            "registry",
            "registry",
            audit_id,
            None,
            "accepted",
            None,
            &[content_hash],
            now,
        )?;
        tx.commit()?;
        Ok(RegistryMutation {
            value: revision_value,
            replayed: false,
        })
    }
}

fn read_registry(
    c: &Connection,
    t: &Tenant,
    kind: Kind,
    id: &str,
    revision: Option<i32>,
) -> Result<Value> {
    kind.validate_id(id)?;
    let (sql, args_rev) = if let Some(revision) = revision {
        if revision < 1 {
            return Err(StoreError::InvalidInput("revision"));
        }
        (format!("SELECT canonical_bytes,content_hash FROM {} WHERE org_id=?1 AND project_id=?2 AND {}=?3 AND revision=?4",kind.revisions(),kind.id()),Some(revision))
    } else {
        (format!("SELECT r.canonical_bytes,r.content_hash FROM {} h JOIN {} r ON(h.org_id=r.org_id AND h.project_id=r.project_id AND h.{}=r.{} AND h.current_revision=r.revision) WHERE h.org_id=?1 AND h.project_id=?2 AND h.{}=?3",kind.table(),kind.revisions(),kind.id(),kind.id(),kind.id()),None)
    };
    let row = if let Some(rev) = args_rev {
        c.query_row(&sql, params![t.org_id, t.project_id, id, rev], read_bytes)
            .optional()?
    } else {
        c.query_row(&sql, params![t.org_id, t.project_id, id], read_bytes)
            .optional()?
    }
    .ok_or(StoreError::NotFound)?;
    verify_revision(c, row, t, kind, Some(id))
}
fn read_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    Ok((row.get(0)?, row.get(1)?))
}
fn verify_revision(
    c: &Connection,
    (bytes, hash): (Vec<u8>, Vec<u8>),
    t: &Tenant,
    kind: Kind,
    id: Option<&str>,
) -> Result<Value> {
    if sha256(&bytes).as_slice() != hash {
        return Err(StoreError::Integrity("registry content hash mismatch"));
    }
    let mut value: Value = serde_json::from_slice(&bytes)?;
    if value["org_id"] != t.org_id
        || value["project_id"] != t.project_id
        || id.is_some_and(|id| value[kind.id()] != id)
    {
        return Err(StoreError::Integrity("registry projection mismatch"));
    }
    value["content_hash"] = Value::String(hex_hash(&hash));
    verify_projection(c, t, kind, &value)?;
    Ok(value)
}
// Recheck the normalized relations used for future snapshot compilation against immutable bytes.
fn verify_projection(c: &Connection, t: &Tenant, kind: Kind, value: &Value) -> Result<()> {
    let id = value[kind.id()]
        .as_str()
        .ok_or(StoreError::Integrity("registry ID"))?;
    let revision = value["revision"]
        .as_i64()
        .ok_or(StoreError::Integrity("registry revision"))?;
    let definition = &value["definition"];
    let expected_previous = value["previous_revision_hash"]
        .as_str()
        .map(decode_hash)
        .transpose()?;
    let expected_time = fw_domain::timestamp(
        value["created_at"]
            .as_str()
            .ok_or(StoreError::Integrity("registry created_at"))?,
    )?;
    match kind {
        Kind::Asset => {
            let projection=c.query_row("SELECT owner_id,kind,criticality,isolation,provenance,created_by,created_at,state,previous_hash FROM asset_revisions WHERE org_id=?1 AND project_id=?2 AND asset_id=?3 AND revision=?4",params![t.org_id,t.project_id,id,revision],|r|Ok((json!({"owner_id":r.get::<_,String>(0)?,"asset_kind":r.get::<_,String>(1)?,"criticality":r.get::<_,String>(2)?,"isolation":r.get::<_,String>(3)?,"provenance":r.get::<_,String>(4)?,"created_by":r.get::<_,String>(5)?,"created_at":r.get::<_,i64>(6)?,"state":r.get::<_,String>(7)?}),r.get::<_,Option<Vec<u8>>>(8)?)))?;
            let expected = json!({"owner_id":definition["owner_id"],"asset_kind":definition["asset_kind"],"criticality":definition["criticality"],"isolation":definition["isolation"],"provenance":definition["provenance"],"created_by":value["created_by"],"created_at":expected_time,"state":value["state"]});
            if projection.0 != expected || projection.1 != expected_previous {
                return Err(StoreError::Integrity("asset projection mismatch"));
            }
            let mut q=c.prepare("SELECT family,network_bytes,prefix,interface_key,interface_label FROM asset_addresses WHERE org_id=?1 AND project_id=?2 AND asset_id=?3 AND revision=?4 ORDER BY family,network_bytes,prefix,interface_key")?;
            let actual = q
                .query_map(params![t.org_id, t.project_id, id, revision], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, u8>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let addresses: Vec<AssetAddress> =
                serde_json::from_value(definition["addresses"].clone())?;
            let mut expected = Vec::new();
            for address in addresses {
                let network = address
                    .cidr
                    .parse::<IpNet>()
                    .map_err(|_| StoreError::Integrity("asset CIDR"))?;
                let (bytes, prefix) = network_bytes(network);
                let interface = address.interface.as_str().map(str::to_owned);
                expected.push((
                    address.family,
                    bytes,
                    prefix,
                    interface.clone().unwrap_or_default(),
                    interface,
                ));
            }
            if actual != expected {
                return Err(StoreError::Integrity("asset address projection mismatch"));
            }
        }
        Kind::Service => {
            let projection=c.query_row("SELECT owner_id,transport_bytes,created_by,created_at,state,previous_hash FROM service_revisions WHERE org_id=?1 AND project_id=?2 AND service_id=?3 AND revision=?4",params![t.org_id,t.project_id,id,revision],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<Vec<u8>>>(5)?)))?;
            if projection.0 != definition["owner_id"]
                || projection.1 != canonical_bytes(&definition["transport"])?
                || projection.2 != value["created_by"]
                || projection.3 != expected_time
                || projection.4 != value["state"]
                || projection.5 != expected_previous
            {
                return Err(StoreError::Integrity("service projection mismatch"));
            }
            for (table, column, property) in [
                ("service_destinations", "asset_id", "destination_asset_ids"),
                ("service_targets", "target_id", "target_ids"),
            ] {
                let mut q=c.prepare(&format!("SELECT {column} FROM {table} WHERE org_id=?1 AND project_id=?2 AND service_id=?3 AND revision=?4 ORDER BY {column}"))?;
                let actual = q
                    .query_map(params![t.org_id, t.project_id, id, revision], |r| {
                        r.get::<_, String>(0)
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                if actual != strings(&definition[property])? {
                    return Err(StoreError::Integrity(
                        "service relation projection mismatch",
                    ));
                }
            }
            let transport: Transport = serde_json::from_value(definition["transport"].clone())?;
            let mut q=c.prepare("SELECT protocol,start,end FROM service_ports WHERE org_id=?1 AND project_id=?2 AND service_id=?3 AND revision=?4 ORDER BY start,end")?;
            let ports = q
                .query_map(params![t.org_id, t.project_id, id, revision], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, u16>(1)?,
                        r.get::<_, u16>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let icmp=c.query_row("SELECT protocol,type,code FROM service_icmp WHERE org_id=?1 AND project_id=?2 AND service_id=?3 AND revision=?4",params![t.org_id,t.project_id,id,revision],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u8>(1)?,r.get::<_,u8>(2)?))).optional()?;
            match transport {
                Transport::Tcp { destination_ports } | Transport::Udp { destination_ports } => {
                    let protocol = definition["transport"]["protocol"]
                        .as_str()
                        .ok_or(StoreError::Integrity("service protocol"))?;
                    let expected = destination_ports
                        .iter()
                        .map(|p| (protocol.to_owned(), p.start, p.end))
                        .collect::<Vec<_>>();
                    if ports != expected || icmp.is_some() {
                        return Err(StoreError::Integrity("service ports projection mismatch"));
                    }
                }
                Transport::Icmp { icmp_type, code } | Transport::Icmpv6 { icmp_type, code } => {
                    let protocol = definition["transport"]["protocol"]
                        .as_str()
                        .ok_or(StoreError::Integrity("service protocol"))?;
                    if !ports.is_empty() || icmp != Some((protocol.to_owned(), icmp_type, code)) {
                        return Err(StoreError::Integrity("service ICMP projection mismatch"));
                    }
                }
            }
        }
    }
    Ok(())
}
fn list_registry(c: &Connection, t: &Tenant, kind: Kind, limit: usize) -> Result<Vec<Value>> {
    valid_limit(limit)?;
    let sql=format!("SELECT r.canonical_bytes,r.content_hash FROM {} h JOIN {} r ON(h.org_id=r.org_id AND h.project_id=r.project_id AND h.{}=r.{} AND h.current_revision=r.revision) WHERE h.org_id=?1 AND h.project_id=?2 ORDER BY h.{} LIMIT ?3",kind.table(),kind.revisions(),kind.id(),kind.id(),kind.id());
    let mut statement = c.prepare(&sql)?;
    let rows = statement
        .query_map(params![t.org_id, t.project_id, limit + 1], read_bytes)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() > limit {
        return Err(StoreError::Conflict("RESULT_TOO_LARGE"));
    }
    rows.into_iter()
        .map(|row| verify_revision(c, row, t, kind, None))
        .collect()
}
fn count_registry(c: &Connection, t: &Tenant, kind: Kind) -> Result<u64> {
    Ok(c.query_row(
        &format!(
            "SELECT count(*) FROM {} WHERE org_id=?1 AND project_id=?2",
            kind.table()
        ),
        params![t.org_id, t.project_id],
        |r| r.get(0),
    )?)
}
fn validate_service_refs(
    c: &Connection,
    t: &Tenant,
    definition: &Value,
    state: &str,
) -> Result<()> {
    for id in strings(&definition["destination_asset_ids"])? {
        let asset = read_registry(c, t, Kind::Asset, id, None)?;
        if state == "active" && asset["state"] != "active" {
            return Err(StoreError::Retired);
        }
        let protocol = definition["transport"]["protocol"].as_str().unwrap_or("");
        if protocol == "icmp" || protocol == "icmpv6" {
            let family = if protocol == "icmp" { "ipv4" } else { "ipv6" };
            if !asset["definition"]["addresses"]
                .as_array()
                .ok_or(StoreError::Integrity("asset addresses"))?
                .iter()
                .any(|a| a["family"] == family)
            {
                return Err(StoreError::InvalidInput("service protocol/family mismatch"));
            }
        }
    }
    for id in strings(&definition["target_ids"])? {
        let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM targets WHERE org_id=?1 AND project_id=?2 AND target_id=?3)",params![t.org_id,t.project_id,id],|r|r.get(0))?;
        if !exists {
            return Err(StoreError::NotFound);
        }
    }
    Ok(())
}
impl AssetWrite {
    fn validate(&mut self) -> Result<()> {
        valid_state(&self.state)?;
        let d = &mut self.definition;
        normalize_text(&mut d.name, 128)?;
        valid_uuid(&d.owner_id)?;
        choice(
            &d.asset_kind,
            &["host", "vm", "namespace", "subnet", "gateway"],
        )?;
        choice(&d.criticality, &["normal", "critical", "management"])?;
        choice(&d.isolation, &["host", "vm", "network_namespace", "subnet"])?;
        if d.provenance != "manual" || !d.source_evidence.is_null() {
            return Err(StoreError::InvalidInput(
                "trusted provenance requires verified enrollment evidence",
            ));
        }
        if d.addresses.is_empty() || d.addresses.len() > 64 {
            return Err(StoreError::InvalidInput("address count"));
        }
        let mut seen = BTreeSet::new();
        for address in &d.addresses {
            let network = address
                .cidr
                .parse::<IpNet>()
                .map_err(|_| StoreError::InvalidInput("CIDR"))?;
            if network.to_string() != address.cidr || network.trunc() != network {
                return Err(StoreError::InvalidInput("noncanonical CIDR"));
            }
            let family = match network {
                IpNet::V4(_) => "ipv4",
                IpNet::V6(n) => {
                    if n.addr().to_ipv4_mapped().is_some() {
                        return Err(StoreError::InvalidInput("IPv4-mapped IPv6"));
                    }
                    "ipv6"
                }
            };
            if address.family != family {
                return Err(StoreError::InvalidInput("CIDR family mismatch"));
            }
            if !address.interface.is_null() {
                let interface = address
                    .interface
                    .as_str()
                    .ok_or(StoreError::InvalidInput("interface"))?;
                if interface.is_empty()
                    || interface.chars().count() > 128
                    || interface.chars().any(char::is_control)
                {
                    return Err(StoreError::InvalidInput("interface"));
                }
            }
            let (bytes, prefix) = network_bytes(network);
            if !seen.insert((
                address.family.clone(),
                bytes,
                prefix,
                address.interface.as_str().unwrap_or("").to_owned(),
            )) {
                return Err(StoreError::InvalidInput("duplicate address"));
            }
        }
        d.addresses.sort_by_key(|a| {
            let (bytes, prefix) = network_bytes(a.cidr.parse::<IpNet>().expect("validated CIDR"));
            (
                a.family.clone(),
                bytes,
                prefix,
                a.interface.as_str().unwrap_or("").to_owned(),
            )
        });
        Ok(())
    }
}
impl ServiceDefinition {
    fn validate(&mut self) -> Result<()> {
        normalize_text(&mut self.name, 128)?;
        normalize_text(&mut self.description, 2048)?;
        valid_uuid(&self.owner_id)?;
        choice(&self.criticality, &["normal", "critical", "management"])?;
        uuid_set(&mut self.destination_asset_ids, 64)?;
        uuid_set(&mut self.target_ids, 16)?;
        if let Transport::Tcp { destination_ports } | Transport::Udp { destination_ports } =
            &mut self.transport
        {
            if destination_ports.is_empty() || destination_ports.len() > 64 {
                return Err(StoreError::InvalidInput("port count"));
            }
            destination_ports.sort();
            if destination_ports
                .iter()
                .any(|p| p.start == 0 || p.start > p.end)
                || destination_ports.windows(2).any(|p| p[0].end >= p[1].start)
            {
                return Err(StoreError::InvalidInput(
                    "invalid or overlapping port ranges",
                ));
            }
        }
        Ok(())
    }
}
fn valid_state(state: &str) -> Result<()> {
    choice(state, &["active", "retired"])
}
fn choice(value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("enum value"))
    }
}
fn normalize_text(text: &mut String, max: usize) -> Result<()> {
    *text = text.nfc().collect();
    if text.is_empty() || text.chars().count() > max || text.chars().any(|c| c == '\0') {
        return Err(StoreError::InvalidInput("text length or NUL"));
    }
    Ok(())
}
fn uuid_set(values: &mut [String], max: usize) -> Result<()> {
    if values.is_empty() || values.len() > max {
        return Err(StoreError::InvalidInput("reference count"));
    }
    for v in values.iter() {
        valid_uuid(v)?;
    }
    values.sort();
    if values.windows(2).any(|p| p[0] == p[1]) {
        return Err(StoreError::InvalidInput("duplicate reference"));
    }
    Ok(())
}
fn service_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
    {
        return Err(StoreError::InvalidInput("service ID"));
    }
    Ok(())
}
fn strings(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .ok_or(StoreError::InvalidInput("reference list"))?
        .iter()
        .map(|v| v.as_str().ok_or(StoreError::InvalidInput("reference")))
        .collect()
}
fn network_bytes(network: IpNet) -> (Vec<u8>, u8) {
    match network {
        IpNet::V4(v) => (v.network().octets().to_vec(), v.prefix_len()),
        IpNet::V6(v) => (v.network().octets().to_vec(), v.prefix_len()),
    }
}
fn decode_hash(value: &str) -> Result<Vec<u8>> {
    let bytes = value
        .strip_prefix("sha256:")
        .ok_or(StoreError::InvalidInput("content hash"))?;
    if bytes.len() != 64
        || !bytes
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StoreError::InvalidInput("content hash"));
    }
    (0..64)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&bytes[i..i + 2], 16)
                .map_err(|_| StoreError::InvalidInput("content hash"))
        })
        .collect()
}
