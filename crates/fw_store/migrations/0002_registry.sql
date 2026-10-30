-- Additive registry catalog. These rows confer neither workload ownership nor firewall authority.
CREATE TABLE assets (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, asset_id TEXT NOT NULL,
 current_revision INTEGER NOT NULL CHECK(current_revision BETWEEN 1 AND 2147483647),
 state TEXT NOT NULL CHECK(state IN ('active','retired')), name TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,asset_id), UNIQUE(org_id,project_id,name),
 FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id),
 FOREIGN KEY(org_id,project_id,asset_id,current_revision) REFERENCES asset_revisions(org_id,project_id,asset_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE asset_revisions (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, asset_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 content_hash BLOB NOT NULL CHECK(length(content_hash)=32), previous_hash BLOB CHECK(previous_hash IS NULL OR length(previous_hash)=32),
 owner_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('host','vm','namespace','subnet','gateway')),
 criticality TEXT NOT NULL CHECK(criticality IN ('normal','critical','management')),
 isolation TEXT NOT NULL CHECK(isolation IN ('host','vm','network_namespace','subnet')),
 provenance TEXT NOT NULL CHECK(provenance='manual'), created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','retired')), canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
 CHECK((revision=1)=(previous_hash IS NULL)),
 PRIMARY KEY(org_id,project_id,asset_id,revision), UNIQUE(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,asset_id) REFERENCES assets(org_id,project_id,asset_id),
 FOREIGN KEY(org_id,project_id,owner_id) REFERENCES principals(org_id,project_id,principal_id),
 FOREIGN KEY(org_id,project_id,created_by) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TABLE asset_addresses (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, asset_id TEXT NOT NULL, revision INTEGER NOT NULL,
 family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')), network_bytes BLOB NOT NULL, prefix INTEGER NOT NULL,
 interface_key TEXT NOT NULL, interface_label TEXT,
 CHECK((family='ipv4' AND length(network_bytes)=4 AND prefix BETWEEN 0 AND 32) OR (family='ipv6' AND length(network_bytes)=16 AND prefix BETWEEN 0 AND 128)),
 PRIMARY KEY(org_id,project_id,asset_id,revision,family,network_bytes,prefix,interface_key),
 FOREIGN KEY(org_id,project_id,asset_id,revision) REFERENCES asset_revisions(org_id,project_id,asset_id,revision)
) STRICT;
CREATE TABLE services (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL,
 current_revision INTEGER NOT NULL CHECK(current_revision BETWEEN 1 AND 2147483647),
 state TEXT NOT NULL CHECK(state IN ('active','retired')), name TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,service_id), UNIQUE(org_id,project_id,name),
 FOREIGN KEY(org_id,project_id) REFERENCES projects(org_id,project_id),
 FOREIGN KEY(org_id,project_id,service_id,current_revision) REFERENCES service_revisions(org_id,project_id,service_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE service_revisions (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 content_hash BLOB NOT NULL CHECK(length(content_hash)=32), previous_hash BLOB CHECK(previous_hash IS NULL OR length(previous_hash)=32),
 owner_id TEXT NOT NULL, transport_bytes BLOB NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','retired')), canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
 CHECK((revision=1)=(previous_hash IS NULL)),
 PRIMARY KEY(org_id,project_id,service_id,revision), UNIQUE(org_id,project_id,content_hash),
 FOREIGN KEY(org_id,project_id,service_id) REFERENCES services(org_id,project_id,service_id),
 FOREIGN KEY(org_id,project_id,owner_id) REFERENCES principals(org_id,project_id,principal_id),
 FOREIGN KEY(org_id,project_id,created_by) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TABLE service_destinations (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL, revision INTEGER NOT NULL, asset_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,service_id,revision,asset_id),
 FOREIGN KEY(org_id,project_id,service_id,revision) REFERENCES service_revisions(org_id,project_id,service_id,revision),
 FOREIGN KEY(org_id,project_id,asset_id) REFERENCES assets(org_id,project_id,asset_id)
) STRICT;
CREATE TABLE service_targets (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL, revision INTEGER NOT NULL, target_id TEXT NOT NULL,
 PRIMARY KEY(org_id,project_id,service_id,revision,target_id),
 FOREIGN KEY(org_id,project_id,service_id,revision) REFERENCES service_revisions(org_id,project_id,service_id,revision),
 FOREIGN KEY(org_id,project_id,target_id) REFERENCES targets(org_id,project_id,target_id)
) STRICT;
CREATE TABLE service_ports (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL, revision INTEGER NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')), start INTEGER NOT NULL CHECK(start BETWEEN 1 AND 65535), end INTEGER NOT NULL CHECK(end BETWEEN start AND 65535),
 PRIMARY KEY(org_id,project_id,service_id,revision,protocol,start,end),
 FOREIGN KEY(org_id,project_id,service_id,revision) REFERENCES service_revisions(org_id,project_id,service_id,revision)
) STRICT;
CREATE TABLE service_icmp (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, service_id TEXT NOT NULL, revision INTEGER NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('icmp','icmpv6')), type INTEGER NOT NULL CHECK(type BETWEEN 0 AND 255), code INTEGER NOT NULL CHECK(code BETWEEN 0 AND 255),
 PRIMARY KEY(org_id,project_id,service_id,revision),
 FOREIGN KEY(org_id,project_id,service_id,revision) REFERENCES service_revisions(org_id,project_id,service_id,revision)
) STRICT;
CREATE TABLE registry_idempotency (
 org_id TEXT NOT NULL, project_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 method TEXT NOT NULL CHECK(method='POST'), route TEXT NOT NULL, key TEXT NOT NULL,
 body_hash BLOB NOT NULL CHECK(length(body_hash)=32), resource_kind TEXT NOT NULL CHECK(resource_kind IN ('asset','service')),
 resource_id TEXT NOT NULL, resource_revision INTEGER NOT NULL,
 response_status INTEGER NOT NULL CHECK(response_status=201), response_bytes BLOB NOT NULL CHECK(length(response_bytes)<=262144),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(org_id,project_id,principal_id,method,route,key),
 FOREIGN KEY(org_id,project_id,principal_id) REFERENCES principals(org_id,project_id,principal_id)
) STRICT;
CREATE TRIGGER asset_revision_no_update BEFORE UPDATE ON asset_revisions BEGIN SELECT RAISE(ABORT,'asset revision immutable'); END;
CREATE TRIGGER asset_revision_no_delete BEFORE DELETE ON asset_revisions BEGIN SELECT RAISE(ABORT,'asset revision immutable'); END;
CREATE TRIGGER asset_address_no_update BEFORE UPDATE ON asset_addresses BEGIN SELECT RAISE(ABORT,'asset address immutable'); END;
CREATE TRIGGER asset_address_no_delete BEFORE DELETE ON asset_addresses BEGIN SELECT RAISE(ABORT,'asset address immutable'); END;
CREATE TRIGGER service_revision_no_update BEFORE UPDATE ON service_revisions BEGIN SELECT RAISE(ABORT,'service revision immutable'); END;
CREATE TRIGGER service_revision_no_delete BEFORE DELETE ON service_revisions BEGIN SELECT RAISE(ABORT,'service revision immutable'); END;
CREATE TRIGGER service_destination_no_update BEFORE UPDATE ON service_destinations BEGIN SELECT RAISE(ABORT,'service destination immutable'); END;
CREATE TRIGGER service_destination_no_delete BEFORE DELETE ON service_destinations BEGIN SELECT RAISE(ABORT,'service destination immutable'); END;
CREATE TRIGGER service_target_no_update BEFORE UPDATE ON service_targets BEGIN SELECT RAISE(ABORT,'service target immutable'); END;
CREATE TRIGGER service_target_no_delete BEFORE DELETE ON service_targets BEGIN SELECT RAISE(ABORT,'service target immutable'); END;
CREATE TRIGGER service_port_no_update BEFORE UPDATE ON service_ports BEGIN SELECT RAISE(ABORT,'service port immutable'); END;
CREATE TRIGGER service_port_no_delete BEFORE DELETE ON service_ports BEGIN SELECT RAISE(ABORT,'service port immutable'); END;
CREATE TRIGGER service_icmp_no_update BEFORE UPDATE ON service_icmp BEGIN SELECT RAISE(ABORT,'service ICMP immutable'); END;
CREATE TRIGGER service_icmp_no_delete BEFORE DELETE ON service_icmp BEGIN SELECT RAISE(ABORT,'service ICMP immutable'); END;
