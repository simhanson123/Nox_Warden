//! Platform-gated entry point for the synthetic isolated Linux fixture tool.
#[cfg(target_os = "linux")]
#[path = "signed_fixture/linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    linux::run_main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ISOLATED_LINUX_ONLY");
    std::process::exit(2);
}
