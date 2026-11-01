#![cfg(target_os = "linux")]
use std::{ffi::OsString, os::unix::ffi::OsStringExt, process::Command};

#[test]
fn non_utf8_arguments_are_refused_without_panicking_or_echoing_private_bytes() {
    let argument = OsString::from_vec(b"/private-observer-key-\xff-secret".to_vec());
    let result = Command::new(env!("CARGO_BIN_EXE_fw_linux_executor"))
        .arg("collect-evidence")
        .arg("--observer-key")
        .arg(argument)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"ARGUMENT_ENCODING\n");
}
