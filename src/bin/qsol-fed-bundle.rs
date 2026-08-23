#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use qsol_fed::verify_bundle;

fn usage() -> &'static str {
    "qsol-fed-bundle verify FILE\n\nVerifies a qsol-fed-bundle/1 entirely offline. No network access is performed."
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!("{}", usage());
        std::process::exit(2);
    };
    let Some(path) = args.next() else {
        eprintln!("{}", usage());
        std::process::exit(2);
    };
    if args.next().is_some() || command != "verify" {
        eprintln!("{}", usage());
        std::process::exit(2);
    }
    let path = PathBuf::from(path);
    let bytes = match fs::read(&path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to read bundle: {error}");
            std::process::exit(2);
        }
    };
    match verify_bundle(&bytes) {
        Ok(report) => {
            println!(
                "bundle_id={} peers={} objects={} authority={} network_required={}",
                report.bundle_id,
                report.peer_count,
                report.object_count,
                report.authority,
                report.network_required
            );
        }
        Err(error) => {
            eprintln!("bundle verification failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_verifier_usage_is_network_free() {
        assert!(usage().contains("entirely offline"));
        assert!(usage().contains("No network access"));
    }
}
