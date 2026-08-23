//! Phase 3 opt-in reference HTTP API.
//!
//! HTTP is a transport surface, not an authority layer. Requests remain bounded,
//! canonical, authenticated, replay-checked, and subject to local routing and
//! Prime Directive admission.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, object_id};
use crate::envelope::{AuthorityClaim, MessageClass, NodeManifest};
use crate::invariants::{admit_effect, AdmissionDecision, FederationEffect};
use crate::replay::{DurableReplayStore, ReplayDecision};
use crate::wire::{
    is_capability_id, is_sha256_ref, ProtocolErrorCode, ProtocolErrorEnvelope,
    ProvenanceObject, PROTOCOL_V1,
};
use crate::{
    verify_signed_envelope, IdentityState, KeyRotationRecord, KeyStatusRecord,
    NodeIdentityDocument, SignatureValidity, SignedEnvelope,
};

pub const PEER_HELLO_SCHEMA_V1: &str = "qsol-fed-peer-hello/1";
pub const API_MAX_BODY_BYTES: usize = 65_536;
pub const API_MAX_CAPABILITIES: usize = 64;
pub const API_MAX_LIFECYCLE_RECORDS: usize = 128;
pub const API_REQUESTS_PER_MINUTE: u32 = 120;
pub const API_POSTS_PER_MINUTE: u32 = 30;
pub const API_MAX_EXPORT_OBJECTS: usize = 4_096;
pub const RATE_LIMIT_CLIENT_IP_HEADER: &str = "x-qsol-client-ip";

#[derive(Debug)]
pub struct ApiBuildError(pub String);

impl std::fmt::Display for ApiBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApiBuildError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerLifecycleRecord {
    Rotation(KeyRotationRecord),
    Status(KeyStatusRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerHello {
    pub schema: String,
    pub protocol: String,
    pub identity: NodeIdentityDocument,
    pub lifecycle: Vec<PeerLifecycleRecord>,
    pub capabilities: Vec<String>,
    pub authority_claim: AuthorityClaim,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilityAdvertisement<'a> {
    protocol: &'a str,
    node_id: &'a str,
    capabilities: &'a [String],
    advertisement_is_authorization: bool,
    authority_claim: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PeerHelloReceipt<'a> {
    protocol: &'a str,
    status: &'static str,
    node_id: &'a str,
    lifecycle_sequence: u64,
    trust: &'static str,
    authority: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EnvelopeReceipt<'a> {
    protocol: &'a str,
    status: &'static str,
    message_id: &'a str,
    signature: &'static str,
    trust: &'static str,
    authority: &'static str,
    admission: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub timestamp_unix: i64,
    pub request_id: u64,
    pub event: String,
    pub method: Option<String>,
    pub route: Option<String>,
    pub status: Option<u16>,
    pub remote_ip: Option<String>,
    pub node_id: Option<String>,
    pub message_id: Option<String>,
    pub decision: Option<String>,
}

struct AuditLog {
    file: Mutex<Option<File>>,
    #[cfg(test)]
    records: Mutex<Vec<AuditRecord>>,
}

impl AuditLog {
    fn open(path: Option<&FsPath>) -> Result<Self, ApiBuildError> {
        let file = if let Some(path) = path {
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|error| ApiBuildError(format!("audit_open:{error}")))?,
            )
        } else {
            None
        };
        Ok(Self {
            file: Mutex::new(file),
            #[cfg(test)]
            records: Mutex::new(Vec::new()),
        })
    }

    fn emit(&self, record: AuditRecord) -> Result<(), ApiBuildError> {
        #[cfg(test)]
        self.records
            .lock()
            .map_err(|_| ApiBuildError("audit_memory_lock_poisoned".into()))?
            .push(record.clone());

        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| ApiBuildError("audit_file_lock_poisoned".into()))?;
        if let Some(file) = file_guard.as_mut() {
            let mut bytes = serde_json::to_vec(&record)
                .map_err(|error| ApiBuildError(format!("audit_encode:{error}")))?;
            bytes.push(b'\n');
            file.write_all(&bytes)
                .map_err(|error| ApiBuildError(format!("audit_write:{error}")))?;
            file.flush()
                .map_err(|error| ApiBuildError(format!("audit_flush:{error}")))?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct RateBucket {
    minute: i64,
    requests: u32,
    posts: u32,
}

#[derive(Default)]
struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, RateBucket>>,
}

impl RateLimiter {
    fn allow(&self, ip: IpAddr, method: &Method, now_unix: i64) -> bool {
        let minute = now_unix.div_euclid(60);
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        let bucket = buckets.entry(ip).or_default();
        if bucket.minute != minute {
            *bucket = RateBucket {
                minute,
                requests: 0,
                posts: 0,
            };
        }
        if bucket.requests >= API_REQUESTS_PER_MINUTE {
            return false;
        }
        if *method == Method::POST && bucket.posts >= API_POSTS_PER_MINUTE {
            return false;
        }
        bucket.requests += 1;
        if *method == Method::POST {
            bucket.posts += 1;
        }
        true
    }
}

struct ApiInner {
    local_identity: NodeIdentityDocument,
    capabilities: Vec<String>,
    peers: RwLock<HashMap<String, IdentityState>>,
    replay: Mutex<DurableReplayStore>,
    objects: RwLock<HashMap<String, Vec<u8>>>,
    provenance: RwLock<HashMap<String, Vec<u8>>>,
    rate_limiter: RateLimiter,
    trusted_proxy: Option<IpAddr>,
    audit: AuditLog,
    request_counter: AtomicU64,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    pub fn new(
        local_identity: NodeIdentityDocument,
        capabilities: Vec<String>,
        replay_path: impl AsRef<FsPath>,
        audit_path: Option<&FsPath>,
    ) -> Result<Self, ApiBuildError> {
        Self::new_with_trusted_proxy(
            local_identity,
            capabilities,
            replay_path,
            audit_path,
            None,
        )
    }

    pub fn new_with_trusted_proxy(
        local_identity: NodeIdentityDocument,
        capabilities: Vec<String>,
        replay_path: impl AsRef<FsPath>,
        audit_path: Option<&FsPath>,
        trusted_proxy: Option<IpAddr>,
    ) -> Result<Self, ApiBuildError> {
        Self::new_with_clock(
            local_identity,
            capabilities,
            replay_path,
            audit_path,
            trusted_proxy,
            Arc::new(system_now_unix),
        )
    }

    fn new_with_clock(
        local_identity: NodeIdentityDocument,
        mut capabilities: Vec<String>,
        replay_path: impl AsRef<FsPath>,
        audit_path: Option<&FsPath>,
        trusted_proxy: Option<IpAddr>,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, ApiBuildError> {
        IdentityState::from_document(&local_identity)
            .map_err(|error| ApiBuildError(format!("local_identity:{error}")))?;
        validate_capabilities(&capabilities)?;
        capabilities.sort();

        let replay_path = prepare_storage_path(replay_path.as_ref())?;
        let audit_path = if let Some(path) = audit_path {
            Some(prepare_storage_path(path)?)
        } else {
            None
        };
        if audit_path.as_ref().is_some_and(|path| path == &replay_path) {
            return Err(ApiBuildError("replay_and_audit_paths_must_be_distinct".into()));
        }

        let replay = DurableReplayStore::open(&replay_path)
            .map_err(|error| ApiBuildError(format!("replay:{error}")))?;
        let audit = AuditLog::open(audit_path.as_deref())?;
        Ok(Self(Arc::new(ApiInner {
            local_identity,
            capabilities,
            peers: RwLock::new(HashMap::new()),
            replay: Mutex::new(replay),
            objects: RwLock::new(HashMap::new()),
            provenance: RwLock::new(HashMap::new()),
            rate_limiter: RateLimiter::default(),
            trusted_proxy,
            audit,
            request_counter: AtomicU64::new(1),
            clock,
        })))
    }

    pub fn node_id(&self) -> &str {
        &self.0.local_identity.node_id
    }

    pub fn capabilities(&self) -> &[String] {
        &self.0.capabilities
    }

    pub fn insert_exportable_object(&self, raw: &[u8]) -> Result<String, ApiBuildError> {
        let canonical = canonicalize(raw).map_err(|error| ApiBuildError(error.0))?;
        let id = object_id(&canonical).map_err(|error| ApiBuildError(error.0))?;
        let mut objects = self
            .0
            .objects
            .write()
            .map_err(|_| ApiBuildError("object_store_lock_poisoned".into()))?;
        if objects.len() >= API_MAX_EXPORT_OBJECTS && !objects.contains_key(&id) {
            return Err(ApiBuildError("export_object_limit_reached".into()));
        }
        objects.insert(id.clone(), canonical);
        Ok(id)
    }

    pub fn insert_exportable_provenance(&self, raw: &[u8]) -> Result<String, ApiBuildError> {
        let canonical = canonicalize(raw).map_err(|error| ApiBuildError(error.0))?;
        let parsed: ProvenanceObject = serde_json::from_slice(&canonical)
            .map_err(|error| ApiBuildError(format!("provenance_schema:{error}")))?;
        if !parsed.validate() {
            return Err(ApiBuildError("provenance_invalid".into()));
        }
        let id = object_id(&canonical).map_err(|error| ApiBuildError(error.0))?;
        let mut provenance = self
            .0
            .provenance
            .write()
            .map_err(|_| ApiBuildError("provenance_store_lock_poisoned".into()))?;
        if provenance.len() >= API_MAX_EXPORT_OBJECTS && !provenance.contains_key(&id) {
            return Err(ApiBuildError("export_provenance_limit_reached".into()));
        }
        provenance.insert(id.clone(), canonical);
        Ok(id)
    }

    #[cfg(test)]
    fn audit_records(&self) -> Vec<AuditRecord> {
        self.0.audit.records()
    }
}

fn prepare_storage_path(path: &FsPath) -> Result<PathBuf, ApiBuildError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| FsPath::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| ApiBuildError(format!("storage_parent:{error}")))?;
    if path.exists() {
        fs::canonicalize(path).map_err(|error| ApiBuildError(format!("storage_path:{error}")))
    } else {
        let parent = fs::canonicalize(parent)
            .map_err(|error| ApiBuildError(format!("storage_parent_canonicalize:{error}")))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| ApiBuildError("storage_path_missing_filename".into()))?;
        Ok(parent.join(file_name))
    }
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), ApiBuildError> {
    if capabilities.len() > API_MAX_CAPABILITIES {
        return Err(ApiBuildError("too_many_capabilities".into()));
    }
    let mut seen = HashSet::new();
    for capability in capabilities {
        if !is_capability_id(capability) || !seen.insert(capability.as_str()) {
            return Err(ApiBuildError("invalid_or_duplicate_capability".into()));
        }
    }
    Ok(())
}

fn rebuild_peer_identity(hello: &PeerHello) -> Result<IdentityState, ApiBuildError> {
    if hello.lifecycle.len() > API_MAX_LIFECYCLE_RECORDS {
        return Err(ApiBuildError("too_many_lifecycle_records".into()));
    }
    let mut state = IdentityState::from_document(&hello.identity)
        .map_err(|error| ApiBuildError(format!("peer_identity:{error}")))?;
    for record in &hello.lifecycle {
        match record {
            PeerLifecycleRecord::Rotation(record) => state
                .apply_rotation(record)
                .map_err(|error| ApiBuildError(format!("peer_rotation:{error}")))?,
            PeerLifecycleRecord::Status(record) => state
                .apply_key_status(record)
                .map_err(|error| ApiBuildError(format!("peer_key_status:{error}")))?,
        }
    }
    Ok(state)
}

fn system_now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn format_wire_time(timestamp: i64) -> Result<String, ApiBuildError> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .ok_or_else(|| ApiBuildError("timestamp_out_of_range".into()))
}

fn canonical_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value)
        .map_err(|error| error.to_string())
        .and_then(|raw| canonicalize(&raw).map_err(|error| error.0))
    {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(_) => protocol_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ProtocolErrorCode::Malformed,
            "response_encoding_failed",
            None,
            None,
            false,
        ),
    }
}

fn protocol_error(
    status: StatusCode,
    code: ProtocolErrorCode,
    message: &str,
    request_message_id: Option<String>,
    invariant_id: Option<String>,
    retryable: bool,
) -> Response {
    let value = ProtocolErrorEnvelope {
        protocol: PROTOCOL_V1.into(),
        error_code: code,
        request_message_id,
        invariant_id,
        message: message.chars().take(512).collect(),
        retryable,
    };
    let bytes = serde_json::to_vec(&value)
        .ok()
        .and_then(|raw| canonicalize(&raw).ok())
        .unwrap_or_else(|| b"{}".to_vec());
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn parse_canonical<T: DeserializeOwned>(raw: &[u8]) -> Result<T, Response> {
    let canonical = canonicalize(raw).map_err(|_| {
        protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "malformed_or_out_of_profile_json",
            None,
            None,
            false,
        )
    })?;
    if canonical != raw {
        return Err(protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "request_json_not_canonical",
            None,
            None,
            false,
        ));
    }
    serde_json::from_slice(&canonical).map_err(|_| {
        protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "request_schema_invalid",
            None,
            None,
            false,
        )
    })
}

fn effect_for_message_class(message_class: MessageClass) -> FederationEffect {
    match message_class {
        MessageClass::Hello => FederationEffect::OfferInformation,
        MessageClass::Capabilities => FederationEffect::AdvertiseCapability,
        MessageClass::EvidenceOffer => FederationEffect::OfferEvidence,
        MessageClass::EvidenceRequest => FederationEffect::RequestEvidence,
        MessageClass::Hypothesis => FederationEffect::OfferHypothesis,
        MessageClass::Challenge => FederationEffect::Challenge,
        MessageClass::Response => FederationEffect::Respond,
        MessageClass::CouncilReport => FederationEffect::SubmitCouncilReport,
        MessageClass::MinorityReport => FederationEffect::SubmitMinorityReport,
        MessageClass::ExperimentReceipt => FederationEffect::SubmitExperimentReceipt,
        MessageClass::Citation => FederationEffect::SubmitCitation,
        MessageClass::Publication => FederationEffect::SubmitPublication,
    }
}

fn remote_addr(request: &Request<Body>) -> SocketAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
}

fn rate_limit_source(state: &ApiState, request: &Request<Body>, remote: SocketAddr) -> Result<IpAddr, Response> {
    let header_name = HeaderName::from_static(RATE_LIMIT_CLIENT_IP_HEADER);
    let supplied = request.headers().get(&header_name);
    match (state.0.trusted_proxy, supplied) {
        (Some(proxy), Some(value)) if remote.ip() == proxy => value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .ok_or_else(|| {
                protocol_error(
                    StatusCode::BAD_REQUEST,
                    ProtocolErrorCode::Malformed,
                    "trusted_proxy_client_ip_invalid",
                    None,
                    None,
                    false,
                )
            }),
        (Some(proxy), None) if remote.ip() == proxy => Err(protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "trusted_proxy_client_ip_required",
            None,
            None,
            false,
        )),
        (_, Some(_)) => Err(protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "forwarded_client_ip_from_untrusted_source",
            None,
            None,
            false,
        )),
        _ => Ok(remote.ip()),
    }
}

fn route_label(path: &str) -> &'static str {
    match path {
        "/fed/v1/node" => "/fed/v1/node",
        "/fed/v1/capabilities" => "/fed/v1/capabilities",
        "/fed/v1/peer/hello" => "/fed/v1/peer/hello",
        "/fed/v1/envelopes" => "/fed/v1/envelopes",
        _ if path.starts_with("/fed/v1/objects/") => "/fed/v1/objects/{sha256}",
        _ if path.starts_with("/fed/v1/provenance/") => "/fed/v1/provenance/{sha256}",
        _ => "unknown",
    }
}

async fn security_middleware(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = state.0.request_counter.fetch_add(1, Ordering::Relaxed);
    let now = (state.0.clock)();
    let remote = remote_addr(&request);
    let method = request.method().clone();
    let route = route_label(request.uri().path()).to_owned();

    if request.uri().query().is_some() {
        return protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "query_parameters_not_admitted",
            None,
            None,
            false,
        );
    }
    let rate_ip = match rate_limit_source(&state, &request, remote) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !state.0.rate_limiter.allow(rate_ip, &method, now) {
        return protocol_error(
            StatusCode::TOO_MANY_REQUESTS,
            ProtocolErrorCode::RateLimited,
            "rate_limit_exceeded",
            None,
            None,
            true,
        );
    }

    let request = if method == Method::POST {
        let content_type_ok = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
        if !content_type_ok {
            return protocol_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ProtocolErrorCode::Malformed,
                "content_type_must_be_application_json",
                None,
                None,
                false,
            );
        }
        if request.headers().contains_key(header::CONTENT_ENCODING) {
            return protocol_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ProtocolErrorCode::Malformed,
                "content_encoding_not_admitted",
                None,
                None,
                false,
            );
        }
        let (parts, body) = request.into_parts();
        let bytes = match to_bytes(body, API_MAX_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return protocol_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ProtocolErrorCode::Malformed,
                    "request_body_too_large",
                    None,
                    None,
                    false,
                )
            }
        };
        Request::from_parts(parts, Body::from(bytes))
    } else {
        request
    };

    let response = next.run(request).await;
    let _ = state.0.audit.emit(AuditRecord {
        timestamp_unix: now,
        request_id,
        event: "http_request".into(),
        method: Some(method.to_string()),
        route: Some(route),
        status: Some(response.status().as_u16()),
        remote_ip: Some(rate_ip.to_string()),
        node_id: None,
        message_id: None,
        decision: None,
    });
    response
}

async fn get_node(State(state): State<ApiState>) -> Response {
    canonical_response(
        StatusCode::OK,
        &NodeManifest {
            protocol: PROTOCOL_V1.into(),
            node_id: state.0.local_identity.node_id.clone(),
            capabilities: state.0.capabilities.clone(),
            authority_claim: AuthorityClaim::None,
        },
    )
}

async fn get_capabilities(State(state): State<ApiState>) -> Response {
    canonical_response(
        StatusCode::OK,
        &CapabilityAdvertisement {
            protocol: PROTOCOL_V1,
            node_id: &state.0.local_identity.node_id,
            capabilities: &state.0.capabilities,
            advertisement_is_authorization: false,
            authority_claim: "none",
        },
    )
}

async fn post_peer_hello(State(state): State<ApiState>, body: Bytes) -> Response {
    let hello: PeerHello = match parse_canonical(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if hello.schema != PEER_HELLO_SCHEMA_V1
        || hello.protocol != PROTOCOL_V1
        || hello.identity.node_id == state.0.local_identity.node_id
        || validate_capabilities(&hello.capabilities).is_err()
        || hello.lifecycle.len() > API_MAX_LIFECYCLE_RECORDS
    {
        return protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "peer_hello_invalid",
            None,
            None,
            false,
        );
    }
    let identity = match rebuild_peer_identity(&hello) {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::UNAUTHORIZED,
                ProtocolErrorCode::AuthenticationFailed,
                "peer_lifecycle_invalid",
                None,
                None,
                false,
            )
        }
    };
    let node_id = hello.identity.node_id.clone();
    let sequence = identity.sequence;
    let mut peers = match state.0.peers.write() {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ProtocolErrorCode::LocalPolicyRejected,
                "peer_registry_unavailable",
                None,
                None,
                true,
            )
        }
    };
    if let Some(existing) = peers.get(&node_id) {
        if identity.sequence < existing.sequence
            || (identity.sequence == existing.sequence && identity != *existing)
        {
            return protocol_error(
                StatusCode::CONFLICT,
                ProtocolErrorCode::Replay,
                "peer_lifecycle_rollback_rejected",
                None,
                None,
                false,
            );
        }
    }
    peers.insert(node_id.clone(), identity);
    drop(peers);

    let now = (state.0.clock)();
    if state
        .0
        .audit
        .emit(AuditRecord {
            timestamp_unix: now,
            request_id: state.0.request_counter.fetch_add(1, Ordering::Relaxed),
            event: "peer_introduced".into(),
            method: None,
            route: Some("/fed/v1/peer/hello".into()),
            status: Some(StatusCode::OK.as_u16()),
            remote_ip: None,
            node_id: Some(node_id.clone()),
            message_id: None,
            decision: Some(format!("introduced_not_trusted_sequence_{sequence}")),
        })
        .is_err()
    {
        return protocol_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ProtocolErrorCode::LocalPolicyRejected,
            "audit_log_unavailable",
            None,
            None,
            true,
        );
    }

    canonical_response(
        StatusCode::OK,
        &PeerHelloReceipt {
            protocol: PROTOCOL_V1,
            status: "introduced",
            node_id: &node_id,
            lifecycle_sequence: sequence,
            trust: "unknown",
            authority: "none",
        },
    )
}

async fn post_envelope(State(state): State<ApiState>, body: Bytes) -> Response {
    let signed = match SignedEnvelope::from_wire(&body) {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::BAD_REQUEST,
                ProtocolErrorCode::Malformed,
                "signed_envelope_invalid",
                None,
                None,
                false,
            )
        }
    };
    let identity = {
        let peers = match state.0.peers.read() {
            Ok(value) => value,
            Err(_) => {
                return protocol_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ProtocolErrorCode::LocalPolicyRejected,
                    "peer_registry_unavailable",
                    Some(signed.envelope.message_id.clone()),
                    None,
                    true,
                )
            }
        };
        match peers.get(&signed.node_id) {
            Some(value) => value.clone(),
            None => {
                return protocol_error(
                    StatusCode::UNAUTHORIZED,
                    ProtocolErrorCode::AuthenticationFailed,
                    "peer_not_introduced",
                    Some(signed.envelope.message_id.clone()),
                    None,
                    false,
                )
            }
        }
    };
    let now = (state.0.clock)();
    let assessment = match verify_signed_envelope(&signed, &identity, now) {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::UNAUTHORIZED,
                ProtocolErrorCode::AuthenticationFailed,
                "envelope_authentication_failed",
                Some(signed.envelope.message_id.clone()),
                None,
                false,
            )
        }
    };
    if assessment.signature != SignatureValidity::Valid {
        return protocol_error(
            StatusCode::UNAUTHORIZED,
            ProtocolErrorCode::AuthenticationFailed,
            "envelope_authentication_failed",
            Some(signed.envelope.message_id.clone()),
            None,
            false,
        );
    }
    if signed.envelope.recipient != state.node_id() {
        return protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::LocalPolicyRejected,
            "envelope_not_addressed_to_local_node",
            Some(signed.envelope.message_id.clone()),
            None,
            false,
        );
    }

    let seen_at = match format_wire_time(now) {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ProtocolErrorCode::LocalPolicyRejected,
                "clock_unavailable",
                Some(signed.envelope.message_id.clone()),
                None,
                true,
            )
        }
    };
    let replay_decision = {
        let mut replay = match state.0.replay.lock() {
            Ok(value) => value,
            Err(_) => {
                return protocol_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ProtocolErrorCode::LocalPolicyRejected,
                    "replay_store_unavailable",
                    Some(signed.envelope.message_id.clone()),
                    None,
                    true,
                )
            }
        };
        match replay.check_and_record(&signed.envelope.message_id, &seen_at) {
            Ok(value) => value,
            Err(_) => {
                return protocol_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ProtocolErrorCode::LocalPolicyRejected,
                    "replay_store_failure",
                    Some(signed.envelope.message_id.clone()),
                    None,
                    true,
                )
            }
        }
    };
    if replay_decision == ReplayDecision::Replay {
        return protocol_error(
            StatusCode::CONFLICT,
            ProtocolErrorCode::Replay,
            "replayed_message",
            Some(signed.envelope.message_id.clone()),
            None,
            false,
        );
    }

    let admission = admit_effect(effect_for_message_class(signed.envelope.message_class));
    let (status, admission_text, invariant) = match admission {
        AdmissionDecision::AcceptAsData => (StatusCode::ACCEPTED, "accepted_as_data", None),
        AdmissionDecision::Quarantine { reason } => {
            (StatusCode::ACCEPTED, "quarantined", Some(reason.to_owned()))
        }
        AdmissionDecision::Reject { invariant_id } => {
            return protocol_error(
                StatusCode::FORBIDDEN,
                ProtocolErrorCode::PrimeDirectiveRejected,
                "prime_directive_rejected",
                Some(signed.envelope.message_id.clone()),
                Some(invariant_id.into()),
                false,
            )
        }
    };

    if state
        .0
        .audit
        .emit(AuditRecord {
            timestamp_unix: now,
            request_id: state.0.request_counter.fetch_add(1, Ordering::Relaxed),
            event: "envelope_admitted".into(),
            method: None,
            route: Some("/fed/v1/envelopes".into()),
            status: Some(status.as_u16()),
            remote_ip: None,
            node_id: Some(signed.node_id.clone()),
            message_id: Some(signed.envelope.message_id.clone()),
            decision: Some(admission_text.into()),
        })
        .is_err()
    {
        return protocol_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ProtocolErrorCode::LocalPolicyRejected,
            "audit_log_unavailable",
            Some(signed.envelope.message_id.clone()),
            invariant,
            true,
        );
    }

    canonical_response(
        status,
        &EnvelopeReceipt {
            protocol: PROTOCOL_V1,
            status: admission_text,
            message_id: &signed.envelope.message_id,
            signature: "valid",
            trust: "unknown",
            authority: "none",
            admission: admission_text,
        },
    )
}

async fn get_object(State(state): State<ApiState>, Path(object_id): Path<String>) -> Response {
    get_local_bytes(&state.0.objects, &object_id, "object_not_exported_locally")
}

async fn get_provenance(State(state): State<ApiState>, Path(object_id): Path<String>) -> Response {
    get_local_bytes(
        &state.0.provenance,
        &object_id,
        "provenance_not_exported_locally",
    )
}

fn get_local_bytes(
    store: &RwLock<HashMap<String, Vec<u8>>>,
    object_id: &str,
    missing: &str,
) -> Response {
    if !is_sha256_ref(object_id) {
        return protocol_error(
            StatusCode::BAD_REQUEST,
            ProtocolErrorCode::Malformed,
            "invalid_object_id",
            None,
            None,
            false,
        );
    }
    let values = match store.read() {
        Ok(value) => value,
        Err(_) => {
            return protocol_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ProtocolErrorCode::LocalPolicyRejected,
                "local_export_registry_unavailable",
                None,
                None,
                true,
            )
        }
    };
    match values.get(object_id) {
        Some(bytes) => json_bytes_response(StatusCode::OK, bytes.clone()),
        None => protocol_error(
            StatusCode::NOT_FOUND,
            ProtocolErrorCode::NotFound,
            missing,
            None,
            None,
            false,
        ),
    }
}

fn json_bytes_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

async fn fallback() -> Response {
    protocol_error(
        StatusCode::NOT_FOUND,
        ProtocolErrorCode::NotFound,
        "route_not_found",
        None,
        None,
        false,
    )
}

pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/fed/v1/node", get(get_node))
        .route("/fed/v1/capabilities", get(get_capabilities))
        .route("/fed/v1/peer/hello", post(post_peer_hello))
        .route("/fed/v1/envelopes", post(post_envelope))
        .route("/fed/v1/objects/{object_id}", get(get_object))
        .route("/fed/v1/provenance/{object_id}", get(get_provenance))
        .fallback(fallback)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::derive_message_id;
    use crate::envelope::FederationEnvelope;
    use crate::{create_identity_document, sign_envelope, LocalSigningKey};
    use axum::http::Request;
    use tower::ServiceExt;

    const LOCAL_ROOT: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const LOCAL_OP: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const PEER_ROOT: &str =
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    const PEER_OP: &str =
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    const NEXT_OP: &str =
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
    const FIXED_NOW: i64 = 1_787_443_320;

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "qsol-fed-api-{label}-{}-{nonce}.log",
            std::process::id()
        ))
    }

    fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
        canonicalize(&serde_json::to_vec(value).unwrap()).unwrap()
    }

    struct TestIdentities {
        local: NodeIdentityDocument,
        peer_root: LocalSigningKey,
        peer: NodeIdentityDocument,
        peer_op: LocalSigningKey,
        peer_state: IdentityState,
    }

    fn identities() -> TestIdentities {
        let local_root = LocalSigningKey::from_seed_hex(LOCAL_ROOT).unwrap();
        let local_op = LocalSigningKey::from_seed_hex(LOCAL_OP).unwrap();
        let local =
            create_identity_document(&local_root, &local_op, "2026-08-23T00:00:00Z").unwrap();
        let peer_root = LocalSigningKey::from_seed_hex(PEER_ROOT).unwrap();
        let peer_op = LocalSigningKey::from_seed_hex(PEER_OP).unwrap();
        let peer =
            create_identity_document(&peer_root, &peer_op, "2026-08-23T00:00:00Z").unwrap();
        let peer_state = IdentityState::from_document(&peer).unwrap();
        TestIdentities {
            local,
            peer_root,
            peer,
            peer_op,
            peer_state,
        }
    }

    fn state() -> ApiState {
        let ids = identities();
        ApiState::new_with_clock(
            ids.local,
            vec!["federation.api/1".into(), "council.report/1".into()],
            temp_path("replay"),
            None,
            None,
            Arc::new(|| FIXED_NOW),
        )
        .unwrap()
    }

    fn signed_peer_envelope(
        peer_state: &IdentityState,
        peer_op: &LocalSigningKey,
        recipient: &str,
    ) -> SignedEnvelope {
        let mut envelope = FederationEnvelope {
            protocol: PROTOCOL_V1.into(),
            message_id: format!("sha256:{}", "0".repeat(64)),
            sender: peer_state.node_id.clone(),
            recipient: recipient.into(),
            message_class: MessageClass::Challenge,
            payload_ref: format!("sha256:{}", "b".repeat(64)),
            provenance_ref: None,
            issued_at: "2026-08-23T00:00:00Z".into(),
            expires_at: Some("2026-08-23T00:05:00Z".into()),
            authority_claim: AuthorityClaim::None,
            signature: (),
        };
        envelope.message_id = derive_message_id(&canonical_json(&envelope)).unwrap();
        sign_envelope(peer_state, peer_op, envelope).unwrap()
    }

    async fn introduce_peer(
        router: Router,
        peer: &NodeIdentityDocument,
        lifecycle: Vec<PeerLifecycleRecord>,
    ) -> (Router, StatusCode) {
        let hello = PeerHello {
            schema: PEER_HELLO_SCHEMA_V1.into(),
            protocol: PROTOCOL_V1.into(),
            identity: peer.clone(),
            lifecycle,
            capabilities: vec!["challenge.exchange/1".into()],
            authority_claim: AuthorityClaim::None,
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/fed/v1/peer/hello")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(canonical_json(&hello)))
                    .unwrap(),
            )
            .await
            .unwrap();
        (router, response.status())
    }

    #[tokio::test]
    async fn discovery_routes_are_canonical_and_non_authoritative() {
        let state = state();
        let router = build_router(state.clone());
        for path in ["/fed/v1/node", "/fed/v1/capabilities"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), API_MAX_BODY_BYTES).await.unwrap();
            assert_eq!(canonicalize(&body).unwrap(), body);
        }
        assert!(state
            .audit_records()
            .iter()
            .all(|record| record.event == "http_request"));
    }

    #[tokio::test]
    async fn hello_then_signed_envelope_is_data_only_and_replay_safe() {
        let state = state();
        let local_id = state.node_id().to_owned();
        let router = build_router(state);
        let ids = identities();
        let (router, status) = introduce_peer(router, &ids.peer, vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let signed = signed_peer_envelope(&ids.peer_state, &ids.peer_op, &local_id);
        let wire = signed.to_wire().unwrap();
        let request = || {
            Request::builder()
                .method(Method::POST)
                .uri("/fed/v1/envelopes")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(wire.clone()))
                .unwrap()
        };
        assert_eq!(
            router.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            router.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn envelope_for_another_node_is_rejected_before_replay() {
        let state = state();
        let router = build_router(state);
        let ids = identities();
        let (router, status) = introduce_peer(router, &ids.peer, vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let signed = signed_peer_envelope(&ids.peer_state, &ids.peer_op, &ids.peer_state.node_id);
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/fed/v1/envelopes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(signed.to_wire().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn peer_lifecycle_reintroduction_cannot_roll_back() {
        let state = state();
        let router = build_router(state);
        let ids = identities();
        let next = LocalSigningKey::from_seed_hex(NEXT_OP).unwrap();
        let rotation = ids
            .peer_state
            .create_transition_rotation(
                &ids.peer_root,
                &ids.peer_op,
                &next,
                "2026-08-23T00:01:00Z",
                "2026-08-23T00:02:00Z",
            )
            .unwrap();
        let (router, status) = introduce_peer(
            router,
            &ids.peer,
            vec![PeerLifecycleRecord::Rotation(rotation)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, stale) = introduce_peer(router, &ids.peer, vec![]).await;
        assert_eq!(stale, StatusCode::CONFLICT);
    }

    #[test]
    fn replay_and_audit_paths_must_be_distinct() {
        let ids = identities();
        let path = temp_path("shared-storage");
        let error = ApiState::new(
            ids.local,
            vec!["federation.api/1".into()],
            &path,
            Some(&path),
        )
        .err()
        .unwrap();
        assert_eq!(error.0, "replay_and_audit_paths_must_be_distinct");
    }

    #[tokio::test]
    async fn trusted_proxy_client_rate_buckets_are_separate() {
        let ids = identities();
        let proxy: IpAddr = "127.0.0.9".parse().unwrap();
        let state = ApiState::new_with_clock(
            ids.local,
            vec!["federation.api/1".into()],
            temp_path("proxy-replay"),
            None,
            Some(proxy),
            Arc::new(|| FIXED_NOW),
        )
        .unwrap();
        let router = build_router(state);
        let proxy_socket = SocketAddr::new(proxy, 4444);
        for _ in 0..API_REQUESTS_PER_MINUTE {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/fed/v1/node")
                        .header(RATE_LIMIT_CLIENT_IP_HEADER, "203.0.113.10")
                        .extension(ConnectInfo(proxy_socket))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let blocked = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/fed/v1/node")
                    .header(RATE_LIMIT_CLIENT_IP_HEADER, "203.0.113.10")
                    .extension(ConnectInfo(proxy_socket))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        let other = router
            .oneshot(
                Request::builder()
                    .uri("/fed/v1/node")
                    .header(RATE_LIMIT_CLIENT_IP_HEADER, "203.0.113.11")
                    .extension(ConnectInfo(proxy_socket))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pseudo_admin_and_ssrf_like_fields_fail_closed() {
        let state = state();
        let router = build_router(state);
        let ids = identities();
        let hello = PeerHello {
            schema: PEER_HELLO_SCHEMA_V1.into(),
            protocol: PROTOCOL_V1.into(),
            identity: ids.peer,
            lifecycle: vec![],
            capabilities: vec!["challenge.exchange/1".into()],
            authority_claim: AuthorityClaim::None,
        };
        let base: serde_json::Value = serde_json::from_slice(&canonical_json(&hello)).unwrap();
        for field in ["force", "trusted", "override", "admin", "fetch_url", "redirect"] {
            let mut hostile = base.clone();
            hostile.as_object_mut().unwrap().insert(
                field.into(),
                serde_json::Value::String("http://169.254.169.254/latest/meta-data".into()),
            );
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/fed/v1/peer/hello")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(canonical_json(&hostile)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "field={field}");
        }
    }

    #[tokio::test]
    async fn limits_content_encoding_and_rate_limits_are_enforced() {
        let state = state();
        let router = build_router(state);
        let oversized = vec![b'a'; API_MAX_BODY_BYTES + 1];
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/fed/v1/peer/hello")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/fed/v1/peer/hello")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn object_and_provenance_routes_are_local_only_and_never_redirect() {
        let state = state();
        let object_id = state.insert_exportable_object(br#"{"a":1}"#).unwrap();
        let provenance_raw = format!(
            "{{\"created_at\":\"2026-08-23T00:00:00Z\",\"parents\":[],\"relation\":\"observed\",\"schema\":\"qsol-fed-provenance/1\",\"source_node\":\"{}\",\"source_object\":\"{}\"}}",
            state.node_id(), object_id
        );
        let provenance_id = state
            .insert_exportable_provenance(provenance_raw.as_bytes())
            .unwrap();
        let router = build_router(state);
        for path in [
            format!("/fed/v1/objects/{object_id}"),
            format!("/fed/v1/provenance/{provenance_id}"),
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_ne!(response.status().as_u16() / 100, 3);
        }
        let missing = router
            .oneshot(
                Request::builder()
                    .uri(format!("/fed/v1/objects/sha256:{}", "f".repeat(64)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn deterministic_fuzz_smoke_never_panics_parser_or_admission() {
        let mut seed = 0x6a09e667f3bcc909u64;
        for length in 0..512usize {
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                bytes.push((seed & 0xff) as u8);
            }
            let _ = canonicalize(&bytes);
            let _ = SignedEnvelope::from_wire(&bytes);
        }
        for effect in [
            FederationEffect::MutateLocalGovernance,
            FederationEffect::PromoteLocalEvidence,
            FederationEffect::CreateOrReweightLocalVote,
            FederationEffect::InstallLocalCapability,
            FederationEffect::RewriteLocalHistory,
            FederationEffect::MutateLocalCitizenship,
            FederationEffect::ExecuteArbitraryLocalTool,
            FederationEffect::ClaimLocalAuthority,
            FederationEffect::DisableConstitutionalInvariant,
            FederationEffect::UnknownAuthorityBearingEffect,
        ] {
            assert!(matches!(
                admit_effect(effect),
                AdmissionDecision::Reject { .. }
            ));
        }
    }
}
