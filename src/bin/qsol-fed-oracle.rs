use std::path::PathBuf;

use qsol_fed::{
    OracleLiveAdapter, OracleTransportQuery, OracleTransportRequest,
    ORACLE_PINNED_COMMIT, ORACLE_RELEASE_FINGERPRINT_SHA256,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("qsol-fed-oracle error: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .ok_or("usage: qsol-fed-oracle <QSOL-ORACLE-root>")?;
    if args.next().is_some() {
        return Err("usage: qsol-fed-oracle <QSOL-ORACLE-root>".into());
    }

    let adapter = OracleLiveAdapter::open(root)?;
    let request = OracleTransportRequest::new(
        "phase5c-conformance",
        OracleTransportQuery {
            event_hash: Some(
                "80468db2bf709982ce4eead9de02ba088306fd365dc999f860139e51987ed8ad"
                    .into(),
            ),
            limit: Some(1),
            ..OracleTransportQuery::default()
        },
    );
    let response = adapter.request(&request)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "status": "verified",
            "oracle_commit": ORACLE_PINNED_COMMIT,
            "oracle_release_fingerprint": ORACLE_RELEASE_FINGERPRINT_SHA256,
            "state": response.observation.state,
            "evidence_refs": response.observation.evidence_refs.len(),
            "authority_effect": response.observation.authority_effect,
            "ledger_mutated": response.ledger_mutated,
            "transport_authority": response.transport_authority,
        }))?
    );
    Ok(())
}
