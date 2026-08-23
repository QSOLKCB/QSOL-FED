// Typed Phase 6 facade for the dependency-free JavaScript reference runtime.
// The .mjs sibling is executable directly by Node; this file supplies the
// TypeScript-facing contract without adding a package-manager dependency.

export type ProtocolDisposition = 'supported' | 'unsupported_major';
export type MessageClass =
  | 'hello' | 'capabilities' | 'evidence.offer' | 'evidence.request'
  | 'hypothesis' | 'challenge' | 'response' | 'council.report'
  | 'minority.report' | 'experiment.receipt' | 'citation' | 'publication';
export type ProvenanceRelation = 'observed' | 'derived' | 'quoted' | 'transported';

export interface NodeManifest {
  protocol: 'qsol-fed/0';
  node_id: string;
  capabilities: string[];
  authority_claim: 'none';
}

export interface ThirdPartyNodeProfile {
  schema: 'third-party-node-profile/1';
  implementation: string;
  governance_model: 'local';
  qsol_governance_adopted: false;
  nexus_required: false;
  council_required: false;
}

export interface ProvenanceObject {
  schema: 'qsol-fed-provenance/1';
  source_node: string;
  source_object: string;
  relation: ProvenanceRelation;
  parents: string[];
  created_at: string;
}

export interface EnvelopeInput {
  sender: string;
  recipient: string;
  message_class: MessageClass;
  payload_ref: string;
  provenance_ref: string | null;
  issued_at: string;
  expires_at: string | null;
}

export interface UnsignedEnvelope extends EnvelopeInput {
  protocol: 'qsol-fed/1';
  message_id: string;
  authority_claim: 'none';
  signature: null;
}

export {
  SDK_CONTRACT,
  BOOTSTRAP_PROTOCOL,
  WIRE_PROTOCOL,
  PROVENANCE_SCHEMA,
  THIRD_PARTY_PROFILE,
  SdkError,
  parse,
  serialize,
  canonicalize,
  objectId,
  deriveMessageId,
  classifyProtocol,
  validateCapabilityId,
  validateNodeManifest,
  buildNodeManifest,
  validateThirdPartyProfile,
  buildProvenance,
  validateProvenance,
  buildUnsignedEnvelope,
  validateUnsignedEnvelope,
  conformanceResult,
} from './qsol_fed_sdk.mjs';
