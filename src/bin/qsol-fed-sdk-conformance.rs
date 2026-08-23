use qsol_fed::{phase6_conformance_from_fixture, sdk_canonicalize};

fn main() {
    if let Err(error) = run() {
        eprintln!("qsol-fed-sdk-conformance error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = include_str!("../../fixtures/phase6/conformance.json");
    let result = phase6_conformance_from_fixture(fixture, "language-neutral")?;
    println!("{}", sdk_canonicalize(&result)?);
    Ok(())
}
