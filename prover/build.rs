use std::env::var;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::Command;

fn get_crate_version(pkg: &str) -> String {
    let cmd = Command::new("cargo")
        .args([
            "tree",
            "--package",
            pkg,
            "--depth",
            "0",
            "--prefix",
            "none",
            "--quiet",
            "--charset",
            "utf8",
        ])
        .output()
        .expect("cargo tree output");

    String::from_utf8(cmd.stdout).expect("utf8 output")
}

fn main() {
    let pkg_version = var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let version = format!(
        "pub const VERSION: &str = \"{}\n{}\";",
        pkg_version,
        get_crate_version("zkevm-circuits"),
    );

    let path = "src/version.rs";
    let update = match File::open(path) {
        Ok(mut file) => {
            let mut buffer = String::new();
            file.read_to_string(&mut buffer).expect("read version.rs");
            buffer != version
        }
        Err(_) => true,
    };

    if update {
        let mut file = File::create(path).expect("create version.rs");
        file.write_all(version.as_bytes())
            .expect("write version.rs");
    }
}
