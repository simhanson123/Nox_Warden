//! Executable startup remains explicit and fixed-diagnostic on every platform.
use std::process::Command;

#[test]
fn explicit_configuration_is_required_without_disclosing_arguments() {
    let result = Command::new(env!("CARGO_BIN_EXE_fw_signer"))
        .arg("private-config-marker")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr).unwrap(),
        "SIGNER_ARGUMENTS_REJECTED\n"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn root_process_is_never_mislabeled_as_controller_separated() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let result = Command::new(env!("CARGO_BIN_EXE_fw_signer"))
        .args(["--config", "/private-config-marker"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr).unwrap(),
        "SIGNER_IDENTITY_REJECTED\n"
    );
}
