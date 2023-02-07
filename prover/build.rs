use std::env::var;
use std::process::Command;

fn run(cmd: &str, args: Vec<&str>) -> String {
    let err = format!("Error running: {} {:#?}", cmd, &args);
    let result = Command::new(cmd).args(&args).output().expect(&err);
    assert!(result.status.success(), "Command failed: {err}");

    String::from_utf8(result.stdout).expect("utf8 output")
}

fn get_crate_version(pkg: &str) -> String {
    run(
        "cargo",
        vec![
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
        ],
    )
}

fn main() {
    let pkg_version = var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let version = format!(
        "{} {} {}",
        pkg_version,
        run(
            "git",
            vec![
                "-c",
                "safe.directory=*",
                "describe",
                "--all",
                "--long",
                "--dirty"
            ]
        ),
        get_crate_version("zkevm-circuits"),
    );
    println!(
        "cargo:rustc-env=PROVER_VERSION={}",
        version.replace('\n', "")
    );
}
