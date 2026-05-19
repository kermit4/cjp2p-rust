fn main() {
    if std::env::var("BUILD_VERSION").is_err() {
        println!("cargo:rustc-env=BUILD_VERSION=unset");
    }
    println!("cargo:rerun-if-env-changed=BUILD_VERSION");
}
