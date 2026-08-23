use qsol_fed::phase6_conformance_from_fixture;

fn main() {
    if let Err(error) = run() {
        eprintln!("qsol-fed-sdk-conformance error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = include_str!("../../fixtures/phase6/conformance.json");
    let result = phase6_conformance_from_fixture(fixture, "language-neutral")?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
