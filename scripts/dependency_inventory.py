#!/usr/bin/env python3
"""Record resolved Cargo package metadata and lockfile checksums; not legal clearance."""
import collections,datetime,hashlib,json,pathlib,subprocess,tomllib
root=pathlib.Path(__file__).resolve().parents[1]
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--offline','--format-version','1'],cwd=root))
lock_bytes=(root/'Cargo.lock').read_bytes()
lock=tomllib.loads(lock_bytes.decode())
checksums={(p['name'],p['version'],p.get('source')):p.get('checksum') for p in lock['package']}
members=set(meta['workspace_members'])
packages=[{'name':p['name'],'version':p['version'],'license_expression':p.get('license'),'source':p.get('source'),'registry_checksum_sha256':checksums.get((p['name'],p['version'],p.get('source'))),'workspace_member':p['id'] in members,'purl':f"pkg:cargo/{p['name']}@{p['version']}"}for p in sorted(meta['packages'],key=lambda p:(p['name'],p['version']))]
report={'schema_version':'fw.dependency-inventory/v1','format':'project dependency inventory; not a certified SPDX or CycloneDX SBOM','generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':'cargo metadata --locked --offline --format-version 1','cargo_lock_sha256':hashlib.sha256(lock_bytes).hexdigest(),'scope':'Resolved Cargo.lock package graph including target-specific dependencies; declarations are upstream package metadata, not legal review or proof of code provenance. Web dependencies are not included.','package_count':len(packages),'workspace_packages':len(members),'license_expression_counts':dict(sorted(collections.Counter(p['license_expression'] or 'UNDECLARED' for p in packages).items())),'packages':packages}
(root/'reports/dependencies.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'packages':len(packages),'workspace_packages':len(members),'cargo_lock_sha256':report['cargo_lock_sha256']}))
