import { createHash } from 'node:crypto';

export const SDK_CONTRACT = 'qsol-fed-sdk/1';
export const BOOTSTRAP_PROTOCOL = 'qsol-fed/0';
export const WIRE_PROTOCOL = 'qsol-fed/1';
export const PROVENANCE_SCHEMA = 'qsol-fed-provenance/1';
export const THIRD_PARTY_PROFILE = 'third-party-node-profile/1';
const MESSAGE_ID_DOMAIN = Buffer.from('qsol-fed-message-id/1\0', 'utf8');
const MAX_INPUT_BYTES = 65536;
const MAX_DEPTH = 32;
const MAX_STRING_UTF8 = 8192;
const MAX_ARRAY_ITEMS = 1024;
const MAX_OBJECT_MEMBERS = 1024;
const NODE_ID = /^fed:qsol:[a-z0-9][a-z0-9._-]{0,127}$/;
const SHA256_REF = /^sha256:[0-9a-f]{64}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const CAPABILITY = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\/[1-9][0-9]*$/;
const MESSAGE_CLASSES = new Set([
  'hello', 'capabilities', 'evidence.offer', 'evidence.request', 'hypothesis',
  'challenge', 'response', 'council.report', 'minority.report',
  'experiment.receipt', 'citation', 'publication',
]);

export class SdkError extends Error {}

function hasLoneSurrogate(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function nfc(value) {
  if (typeof value !== 'string' || hasLoneSurrogate(value)) throw new SdkError('lone_surrogate');
  const normalized = value.normalize('NFC');
  if (Buffer.byteLength(normalized, 'utf8') > MAX_STRING_UTF8) throw new SdkError('string_too_large');
  return normalized;
}

function scalarLength(value) { return Array.from(value).length; }
function isNodeId(value) { return typeof value === 'string' && NODE_ID.test(value); }
function isSha256Ref(value) { return typeof value === 'string' && SHA256_REF.test(value); }
function isTimestamp(value) { return typeof value === 'string' && TIMESTAMP.test(value); }

function compareUnicodeScalars(left, right) {
  const a = Array.from(left);
  const b = Array.from(right);
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const ac = a[i].codePointAt(0);
    const bc = b[i].codePointAt(0);
    if (ac !== bc) return ac - bc;
  }
  return a.length - b.length;
}

class Parser {
  constructor(text) { this.text = text; this.i = 0; }
  skip() {
    while (this.i < this.text.length) {
      const ch = this.text[this.i];
      if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') break;
      this.i++;
    }
  }
  value(depth = 1) {
    if (depth > MAX_DEPTH) throw new SdkError('max_depth_exceeded');
    this.skip();
    const ch = this.text[this.i];
    if (ch === '"') return this.string();
    if (ch === '[') return this.array(depth);
    if (ch === '{') return this.object(depth);
    if (this.text.startsWith('true', this.i)) { this.i += 4; return true; }
    if (this.text.startsWith('false', this.i)) { this.i += 5; return false; }
    if (this.text.startsWith('null', this.i)) { this.i += 4; return null; }
    return this.number();
  }
  string() {
    const start = this.i++;
    let escaped = false;
    while (this.i < this.text.length) {
      const ch = this.text[this.i++];
      if (escaped) { escaped = false; continue; }
      if (ch === '\\') { escaped = true; continue; }
      if (ch === '"') {
        let value;
        try { value = JSON.parse(this.text.slice(start, this.i)); } catch { throw new SdkError('malformed_json'); }
        return nfc(value);
      }
      if (ch.charCodeAt(0) < 0x20) throw new SdkError('malformed_json');
    }
    throw new SdkError('malformed_json');
  }
  number() {
    const tail = this.text.slice(this.i);
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(tail);
    if (!match) throw new SdkError('malformed_json');
    this.i += match[0].length;
    if (/[.eE]/.test(this.text[this.i] ?? '')) throw new SdkError('non_integer_number');
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value)) throw new SdkError('integer_out_of_range');
    return value;
  }
  array(depth) {
    this.i++; this.skip();
    const values = [];
    if (this.text[this.i] === ']') { this.i++; return values; }
    for (;;) {
      if (values.length >= MAX_ARRAY_ITEMS) throw new SdkError('too_many_array_items');
      values.push(this.value(depth + 1)); this.skip();
      const ch = this.text[this.i++];
      if (ch === ']') return values;
      if (ch !== ',') throw new SdkError('malformed_json');
    }
  }
  object(depth) {
    this.i++; this.skip();
    const result = Object.create(null);
    const rawSeen = new Set();
    const nfcSeen = new Set();
    if (this.text[this.i] === '}') { this.i++; return result; }
    for (;;) {
      if (rawSeen.size >= MAX_OBJECT_MEMBERS) throw new SdkError('too_many_object_members');
      this.skip();
      if (this.text[this.i] !== '"') throw new SdkError('malformed_json');
      const rawStart = this.i;
      const key = this.string();
      const rawKey = this.text.slice(rawStart, this.i);
      if (rawSeen.has(rawKey)) throw new SdkError('duplicate_key');
      rawSeen.add(rawKey);
      if (nfcSeen.has(key)) throw new SdkError('normalized_duplicate_key');
      nfcSeen.add(key);
      this.skip();
      if (this.text[this.i++] !== ':') throw new SdkError('malformed_json');
      result[key] = this.value(depth + 1); this.skip();
      const ch = this.text[this.i++];
      if (ch === '}') return result;
      if (ch !== ',') throw new SdkError('malformed_json');
    }
  }
}

export function parse(raw) {
  let text;
  let bytes;
  if (Buffer.isBuffer(raw)) {
    bytes = raw;
    if (bytes.length > MAX_INPUT_BYTES) throw new SdkError('input_too_large');
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new SdkError('utf8_bom_forbidden');
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { throw new SdkError('invalid_utf8'); }
  } else if (typeof raw === 'string') {
    if (hasLoneSurrogate(raw)) throw new SdkError('lone_surrogate');
    text = raw;
    bytes = Buffer.from(text, 'utf8');
    if (bytes.length > MAX_INPUT_BYTES) throw new SdkError('input_too_large');
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new SdkError('utf8_bom_forbidden');
  } else {
    throw new SdkError('malformed_json');
  }
  const parser = new Parser(text);
  const value = parser.value(); parser.skip();
  if (parser.i !== text.length) throw new SdkError('malformed_json');
  return value;
}

function normalizeConstructed(value, depth = 1) {
  if (depth > MAX_DEPTH) throw new SdkError('max_depth_exceeded');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new SdkError('integer_out_of_range');
    return value;
  }
  if (typeof value === 'string') return nfc(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) throw new SdkError('too_many_array_items');
    return value.map(child => normalizeConstructed(child, depth + 1));
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length > MAX_OBJECT_MEMBERS) throw new SdkError('too_many_object_members');
    const result = Object.create(null); const seen = new Set();
    for (const raw of keys) {
      const key = nfc(raw);
      if (seen.has(key)) throw new SdkError('normalized_duplicate_key');
      seen.add(key); result[key] = normalizeConstructed(value[raw], depth + 1);
    }
    return result;
  }
  throw new SdkError('unsupported_value');
}

function escapeString(value) {
  value = nfc(value);
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return out + '"';
}

export function serialize(value) {
  value = normalizeConstructed(value);
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return escapeString(value);
  if (Array.isArray(value)) return '[' + value.map(serialize).join(',') + ']';
  const keys = Object.keys(value).sort(compareUnicodeScalars);
  return '{' + keys.map(key => escapeString(key) + ':' + serialize(value[key])).join(',') + '}';
}

export function canonicalize(value) {
  const normalized = typeof value === 'string' || Buffer.isBuffer(value) ? parse(value) : normalizeConstructed(value);
  const bytes = Buffer.from(serialize(normalized), 'utf8');
  if (bytes.length > MAX_INPUT_BYTES) throw new SdkError('output_too_large');
  return bytes;
}

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
export function objectId(value) { return 'sha256:' + sha256(canonicalize(value)); }
export function deriveMessageId(envelope) {
  if (!envelope || typeof envelope !== 'object' || !Object.hasOwn(envelope, 'message_id') || !Object.hasOwn(envelope, 'signature')) throw new SdkError('envelope_projection_fields_missing');
  const projection = { ...envelope }; delete projection.message_id; delete projection.signature;
  return 'sha256:' + sha256(Buffer.concat([MESSAGE_ID_DOMAIN, canonicalize(projection)]));
}
export function classifyProtocol(protocol) { return protocol === WIRE_PROTOCOL ? 'supported' : 'unsupported_major'; }
export function validateCapabilityId(value) { return typeof value === 'string' && CAPABILITY.test(value); }

export function validateNodeManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') throw new SdkError('sdk_node_manifest_invalid');
  const keys = Object.keys(manifest).sort().join(',');
  if (keys !== 'authority_claim,capabilities,node_id,protocol' || manifest.protocol !== BOOTSTRAP_PROTOCOL || manifest.authority_claim !== 'none' || !isNodeId(manifest.node_id)) throw new SdkError('sdk_node_manifest_invalid');
  if (!Array.isArray(manifest.capabilities) || manifest.capabilities.length > 64 || new Set(manifest.capabilities).size !== manifest.capabilities.length || !manifest.capabilities.every(validateCapabilityId)) throw new SdkError('sdk_node_manifest_invalid');
}
export function buildNodeManifest(nodeId, capabilities) {
  if (!Array.isArray(capabilities)) throw new SdkError('sdk_node_manifest_invalid');
  const value = { protocol: BOOTSTRAP_PROTOCOL, node_id: nodeId, capabilities: [...capabilities], authority_claim: 'none' };
  validateNodeManifest(value); return value;
}
export function validateThirdPartyProfile(profile) {
  if (!profile || typeof profile !== 'object') throw new SdkError('third_party_profile_invalid');
  const keys = Object.keys(profile).sort().join(',');
  if (keys !== 'council_required,governance_model,implementation,nexus_required,qsol_governance_adopted,schema' || profile.schema !== THIRD_PARTY_PROFILE || profile.governance_model !== 'local' || typeof profile.implementation !== 'string' || scalarLength(profile.implementation) < 1 || scalarLength(profile.implementation) > 128 || profile.qsol_governance_adopted !== false || profile.nexus_required !== false || profile.council_required !== false) throw new SdkError('third_party_profile_invalid');
}
export function buildProvenance(sourceNode, sourceObject, relation, parents, createdAt) {
  if (!Array.isArray(parents)) throw new SdkError('sdk_provenance_invalid');
  const value = { schema: PROVENANCE_SCHEMA, source_node: sourceNode, source_object: sourceObject, relation, parents: [...parents], created_at: createdAt };
  validateProvenance(value); return value;
}
export function validateProvenance(value) {
  if (!value || typeof value !== 'object') throw new SdkError('sdk_provenance_invalid');
  const keys = Object.keys(value).sort().join(',');
  if (keys !== 'created_at,parents,relation,schema,source_node,source_object' || value.schema !== PROVENANCE_SCHEMA || !isNodeId(value.source_node) || !isSha256Ref(value.source_object) || typeof value.relation !== 'string' || !['observed','derived','quoted','transported'].includes(value.relation) || !isTimestamp(value.created_at)) throw new SdkError('sdk_provenance_invalid');
  if (!Array.isArray(value.parents) || value.parents.length > 64 || new Set(value.parents).size !== value.parents.length || !value.parents.every(isSha256Ref)) throw new SdkError('sdk_provenance_invalid');
}
function validateEnvelopeSpec(spec, error) {
  if (!spec || typeof spec !== 'object') throw new SdkError(error);
  const required = ['expires_at','issued_at','message_class','payload_ref','provenance_ref','recipient','sender'].sort().join(',');
  if (Object.keys(spec).sort().join(',') !== required || !isNodeId(spec.sender) || !isNodeId(spec.recipient) || typeof spec.message_class !== 'string' || !MESSAGE_CLASSES.has(spec.message_class) || !isSha256Ref(spec.payload_ref) || (spec.provenance_ref !== null && !isSha256Ref(spec.provenance_ref)) || !isTimestamp(spec.issued_at) || (spec.expires_at !== null && !isTimestamp(spec.expires_at))) throw new SdkError(error);
}
export function buildUnsignedEnvelope(spec) {
  validateEnvelopeSpec(spec, 'sdk_envelope_input_invalid');
  const envelope = { protocol: WIRE_PROTOCOL, message_id: 'sha256:' + '0'.repeat(64), sender: spec.sender, recipient: spec.recipient, message_class: spec.message_class, payload_ref: spec.payload_ref, provenance_ref: spec.provenance_ref, issued_at: spec.issued_at, expires_at: spec.expires_at, authority_claim: 'none', signature: null };
  envelope.message_id = deriveMessageId(envelope); validateUnsignedEnvelope(envelope); return envelope;
}
export function validateUnsignedEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new SdkError('sdk_envelope_invalid');
  const required = ['authority_claim','expires_at','issued_at','message_class','message_id','payload_ref','protocol','provenance_ref','recipient','sender','signature'].sort().join(',');
  if (Object.keys(envelope).sort().join(',') !== required || envelope.protocol !== WIRE_PROTOCOL || envelope.authority_claim !== 'none' || envelope.signature !== null || !isSha256Ref(envelope.message_id)) throw new SdkError('sdk_envelope_invalid');
  validateEnvelopeSpec({ sender: envelope.sender, recipient: envelope.recipient, message_class: envelope.message_class, payload_ref: envelope.payload_ref, provenance_ref: envelope.provenance_ref, issued_at: envelope.issued_at, expires_at: envelope.expires_at }, 'sdk_envelope_invalid');
  if (deriveMessageId(envelope) !== envelope.message_id) throw new SdkError('sdk_envelope_invalid');
}

export function conformanceResult(fixture) {
  if (fixture.schema !== 'qsol-fed-sdk-conformance/1' || fixture.wire_protocol !== WIRE_PROTOCOL) throw new SdkError('phase6_fixture_contract_invalid');
  validateNodeManifest(fixture.node_manifest); validateThirdPartyProfile(fixture.third_party_profile);
  const source = fixture.provenance;
  const provenance = buildProvenance(source.source_node, source.source_object, source.relation, source.parents, source.created_at);
  const hello = buildUnsignedEnvelope(fixture.hello); const evidence = buildUnsignedEnvelope(fixture.evidence_offer);
  const result = {
    schema: 'qsol-fed-sdk-conformance-result/1', implementation: 'language-neutral',
    node_manifest_canonical: canonicalize(fixture.node_manifest).toString(), node_manifest_object_id: objectId(fixture.node_manifest),
    profile_canonical: canonicalize(fixture.third_party_profile).toString(), profile_object_id: objectId(fixture.third_party_profile),
    payload_canonical: canonicalize(fixture.payload).toString(), payload_object_id: objectId(fixture.payload),
    provenance_canonical: canonicalize(provenance).toString(), provenance_object_id: objectId(provenance),
    hello_canonical: canonicalize(hello).toString(), hello_message_id: hello.message_id,
    evidence_canonical: canonicalize(evidence).toString(), evidence_message_id: evidence.message_id,
    qsol_governance_adopted: fixture.third_party_profile.qsol_governance_adopted,
    nexus_required: fixture.third_party_profile.nexus_required,
    council_required: fixture.third_party_profile.council_required,
    authority_effect: 'none',
  };
  for (const [key, expected] of Object.entries(fixture.expected)) if (result[key] !== expected) throw new SdkError(`phase6_expected_mismatch:${key}`);
  return result;
}
