//! The native execution test adapter is available only on Linux.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{Error, Result, native};

fn main() {
    #[cfg(target_os = "linux")]
    linux::run_main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("UNSUPPORTED_PLATFORM: isolated native executor requires Linux");
        std::process::exit(2);
    }
}
