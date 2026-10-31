//! Test storage must satisfy the same private-directory policy as an operator's
//! authority storage, regardless of the runner's umask or inherited default ACL.

pub fn private_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix("nox-authority-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Apply the mode to mkdir itself; do not create a writable directory and
        // tighten it after opening authority databases or writing fixture keys.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().expect("create private authority fixture")
}
