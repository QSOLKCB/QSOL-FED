#![forbid(unsafe_code)]

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use qsol_fed::{build_router, ApiState, NodeIdentityDocument};

#[derive(Debug)]
struct Args {
    listen: SocketAddr,
    identity: PathBuf,
    replay_log: PathBuf,
    audit_log: PathBuf,
    capabilities: Vec<String>,
    allow_public_listen: bool,
    tls_terminated_upstream: bool,
    trusted_proxy: Option<IpAddr>,
}

fn usage() -> &'static str {
    "qsol-fed --identity FILE [--listen ADDR] [--replay-log FILE] [--audit-log FILE] [--capability ID ...] [--allow-public-listen --tls-terminated-upstream --trusted-proxy IP]\n\nDefault listen address: 127.0.0.1:8787"
}

fn parse_args_from<I>(values: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut listen: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    let mut identity = None;
    let mut replay_log = PathBuf::from("qsol-fed-replay.log");
    let mut audit_log = PathBuf::from("qsol-fed-audit.jsonl");
    let mut capabilities = vec!["federation.api/1".to_owned()];
    let mut allow_public_listen = false;
    let mut tls_terminated_upstream = false;
    let mut trusted_proxy = None;

    let mut args = values.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                let value = args.next().ok_or("--listen requires a value")?;
                listen = value.parse().map_err(|_| format!("invalid listen address: {value}"))?;
            }
            "--identity" => identity = Some(PathBuf::from(args.next().ok_or("--identity requires a value")?)),
            "--replay-log" => replay_log = PathBuf::from(args.next().ok_or("--replay-log requires a value")?),
            "--audit-log" => audit_log = PathBuf::from(args.next().ok_or("--audit-log requires a value")?),
            "--capability" => capabilities.push(args.next().ok_or("--capability requires a value")?),
            "--trusted-proxy" => {
                let value = args.next().ok_or("--trusted-proxy requires a value")?;
                trusted_proxy = Some(value.parse().map_err(|_| format!("invalid trusted proxy IP: {value}"))?);
            }
            "--allow-public-listen" => allow_public_listen = true,
            "--tls-terminated-upstream" => tls_terminated_upstream = true,
            "--help" | "-h" => return Err(usage().to_owned()),
            other => return Err(format!("unknown argument: {other}\n\n{}", usage())),
        }
    }

    let identity = identity.ok_or_else(|| format!("--identity is required\n\n{}", usage()))?;
    if !listen.ip().is_loopback() && !(allow_public_listen && tls_terminated_upstream && trusted_proxy.is_some()) {
        return Err("non-loopback listening requires --allow-public-listen, --tls-terminated-upstream, and --trusted-proxy IP".into());
    }

    capabilities.sort();
    capabilities.dedup();
    Ok(Args {
        listen,
        identity,
        replay_log,
        audit_log,
        capabilities,
        allow_public_listen,
        tls_terminated_upstream,
        trusted_proxy,
    })
}

fn parse_args() -> Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let identity_bytes = match fs::read(&args.identity) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read identity document: {error}");
            std::process::exit(2);
        }
    };
    let identity: NodeIdentityDocument = match serde_json::from_slice(&identity_bytes) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("invalid identity document JSON: {error}");
            std::process::exit(2);
        }
    };
    let state = match ApiState::new_with_trusted_proxy(
        identity,
        args.capabilities,
        &args.replay_log,
        Some(&args.audit_log),
        args.trusted_proxy,
    ) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("failed to initialize API state: {error}");
            std::process::exit(2);
        }
    };
    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind {}: {error}", args.listen);
            std::process::exit(2);
        }
    };

    eprintln!(
        "qsol-fed reference API listening on {} (public_opt_in={}, tls_terminated_upstream={}, trusted_proxy={:?})",
        args.listen, args.allow_public_listen, args.tls_terminated_upstream, args.trusted_proxy
    );

    let service = build_router(state).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(error) = axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<String> {
        vec!["--identity".into(), "node.json".into()]
    }

    #[test]
    fn loopback_remains_default() {
        let parsed = parse_args_from(base_args()).unwrap();
        assert!(parsed.listen.ip().is_loopback());
        assert!(parsed.trusted_proxy.is_none());
    }

    #[test]
    fn public_listen_requires_tls_and_trusted_proxy() {
        let mut incomplete = base_args();
        incomplete.extend([
            "--listen".into(),
            "0.0.0.0:8787".into(),
            "--allow-public-listen".into(),
            "--tls-terminated-upstream".into(),
        ]);
        assert!(parse_args_from(incomplete).is_err());

        let mut complete = base_args();
        complete.extend([
            "--listen".into(),
            "0.0.0.0:8787".into(),
            "--allow-public-listen".into(),
            "--tls-terminated-upstream".into(),
            "--trusted-proxy".into(),
            "127.0.0.1".into(),
        ]);
        assert!(parse_args_from(complete).is_ok());
    }
}
