fn main() {
    if let Err(e) = cjp2p_ctl::cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
