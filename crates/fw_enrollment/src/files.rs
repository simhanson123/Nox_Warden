use crate::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
};

#[cfg(unix)]
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir) {
            return Err(EnrollmentError::Invalid("parent traversal in private path"));
        }
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EnrollmentError::Invalid("symlink in private path"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(EnrollmentError::Invalid(
            "private directory ownership or permissions",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_private(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    private_directory(
        path.parent()
            .ok_or(EnrollmentError::Invalid("private file parent"))?,
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_PEM as u64
    {
        return Err(EnrollmentError::Invalid(
            "private file ownership, links, permissions or size",
        ));
    }
    let mut result = Vec::new();
    (&mut file)
        .take((MAX_PEM + 1) as u64)
        .read_to_end(&mut result)?;
    if result.len() > MAX_PEM {
        return Err(EnrollmentError::Invalid("private file size"));
    }
    Ok(result)
}

#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    private_directory(
        path.parent()
            .ok_or(EnrollmentError::Invalid("private file parent"))?,
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Create a new private directory with distinct CA and server transport keys.
/// An existing directory is never overwritten or silently assigned a new root.
#[cfg(unix)]
pub fn init_controller_pki(directory: &Path, now: i64) -> Result<ControllerPki> {
    use std::os::unix::fs::DirBuilderExt;
    if !valid_time(now) || now < 60 || now.checked_add(365 * 86_400).is_none_or(|t| !valid_time(t))
    {
        return Err(EnrollmentError::Time);
    }
    reject_symlink_components(directory)?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    private_directory(directory)?;
    let ca_key = PKey::generate_ed25519()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Nox local enrollment CA")?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut serial = [0u8; 20];
    rand_bytes(&mut serial)?;
    serial[0] &= 0x7f;
    serial[19] |= 1;
    let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&ca_key)?;
    builder.set_not_before(Asn1Time::from_unix(now - 60)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(now + 365 * 86_400)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    let key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(key_id)?;
    let authority_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(authority_id)?;
    builder.sign(&ca_key, MessageDigest::null())?;
    let ca = builder.build();
    let ca_pem = utf8_pem(ca.to_pem()?)?;
    let ca_key_pem = ca_key.private_key_to_pem_pkcs8()?;
    let authority = CertificateAuthority::from_pem(&ca_pem, &ca_key_pem, now)?;
    let server_key = PKey::generate_ed25519()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut serial = [0u8; 20];
    rand_bytes(&mut serial)?;
    serial[0] &= 0x7f;
    serial[19] |= 1;
    let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "localhost")?;
    builder.set_subject_name(&name.build())?;
    builder.set_issuer_name(ca.subject_name())?;
    builder.set_pubkey(&server_key)?;
    builder.set_not_before(Asn1Time::from_unix(now - 60)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(now + 30 * 86_400)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .ip("::1")
        .build(&builder.x509v3_context(Some(&ca), None))?;
    builder.append_extension(san)?;
    let subject_key_id =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&ca), None))?;
    builder.append_extension(subject_key_id)?;
    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(&ca), None))?;
    builder.append_extension(authority_key_id)?;
    builder.sign(&ca_key, MessageDigest::null())?;
    let server = builder.build();
    verify_chain(&server, &ca, now, X509PurposeId::SSL_SERVER)?;
    let server_certificate_pem = format!("{}{}", utf8_pem(server.to_pem()?)?, ca_pem);
    let server_private_key_pem = utf8_pem(server_key.private_key_to_pem_pkcs8()?)?;
    write_new(&directory.join("ca.pem"), ca_pem.as_bytes())?;
    write_new(&directory.join("ca-key.pem"), &ca_key_pem)?;
    write_new(
        &directory.join("server.pem"),
        server_certificate_pem.as_bytes(),
    )?;
    write_new(
        &directory.join("server-key.pem"),
        server_private_key_pem.as_bytes(),
    )?;
    File::open(directory)?.sync_all()?;
    Ok(ControllerPki {
        authority,
        server_certificate_pem,
        server_private_key_pem,
    })
}

#[cfg(unix)]
pub fn load_controller_pki(directory: &Path, now: i64) -> Result<ControllerPki> {
    private_directory(directory)?;
    let ca_pem = utf8_pem(read_private(&directory.join("ca.pem"))?)?;
    let ca_key = read_private(&directory.join("ca-key.pem"))?;
    let authority = CertificateAuthority::from_pem(&ca_pem, &ca_key, now)?;
    let server_certificate_pem = utf8_pem(read_private(&directory.join("server.pem"))?)?;
    let server_private_key_pem = utf8_pem(read_private(&directory.join("server-key.pem"))?)?;
    one_pem(&server_private_key_pem, "PRIVATE KEY", MAX_PEM)?;
    let key = PKey::private_key_from_pem(server_private_key_pem.as_bytes())?;
    require_ed25519(&key)?;
    let chain = X509::stack_from_pem(server_certificate_pem.as_bytes())?;
    if chain.len() != 2
        || chain[1].to_der()? != authority.certificate.to_der()?
        || [chain[0].to_pem()?, chain[1].to_pem()?].concat() != server_certificate_pem.as_bytes()
        || !chain[0].public_key()?.public_eq(&key)
        || key.public_eq(&authority.key)
    {
        return Err(EnrollmentError::Verification);
    }
    verify_chain(
        &chain[0],
        &authority.certificate,
        now,
        X509PurposeId::SSL_SERVER,
    )?;
    let names = chain[0]
        .subject_alt_names()
        .ok_or(EnrollmentError::Verification)?;
    if names.len() != 3
        || !names.iter().any(|n| n.dnsname() == Some("localhost"))
        || !names.iter().any(|n| n.ipaddress() == Some(&[127, 0, 0, 1]))
        || !names
            .iter()
            .any(|n| n.ipaddress() == Some(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
    {
        return Err(EnrollmentError::Verification);
    }
    Ok(ControllerPki {
        authority,
        server_certificate_pem,
        server_private_key_pem,
    })
}

#[cfg(not(unix))]
pub fn init_controller_pki(_directory: &Path, _now: i64) -> Result<ControllerPki> {
    Err(EnrollmentError::Invalid(
        "protected PKI storage currently requires Unix",
    ))
}
#[cfg(not(unix))]
pub fn load_controller_pki(_directory: &Path, _now: i64) -> Result<ControllerPki> {
    Err(EnrollmentError::Invalid(
        "protected PKI storage currently requires Unix",
    ))
}
