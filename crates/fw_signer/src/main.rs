fn main() {
    if let Err(error) = fw_signer::run(std::env::args_os().collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
