#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  SdkError,
  buildProvenance,
  buildUnsignedEnvelope,
  canonicalize,
  parse,
  validateThirdPartyProfile,
} from './qsol_fed_sdk.mjs';

function mustReject(fn, message) {
  let rejected = false;
  try { fn(); } catch (error) {
    rejected = error instanceof SdkError;
  }
  assert.equal(rejected, true, message);
}

mustReject(
  () => parse(Buffer.from([0x22, 0xff, 0x22])),
  'invalid UTF-8 buffer must fail closed',
);

mustReject(() => canonicalize('\u00a0null'), 'NBSP prefix is not JSON whitespace');
mustReject(() => canonicalize('null\u00a0'), 'NBSP suffix is not JSON whitespace');
mustReject(() => canonicalize('"\\ud800"'), 'lone surrogate must fail closed');

const ordered = canonicalize({ '\u{10000}': 0, '\ue000': 1 }).toString('utf8');
assert.equal(ordered, '{"":1,"𐀀":0}', 'keys must sort by Unicode scalar value');

const envelopeSpec = {
  sender: new String('fed:qsol:neutral-lab-01'),
  recipient: 'fed:qsol:reference-node',
  message_class: 'hello',
  payload_ref: 'sha256:' + '2'.repeat(64),
  provenance_ref: null,
  issued_at: '2026-08-23T00:00:00Z',
  expires_at: null,
};
mustReject(() => buildUnsignedEnvelope(envelopeSpec), 'boxed sender string must reject');

mustReject(
  () => buildProvenance(
    'fed:qsol:neutral-lab-01',
    'sha256:' + '1'.repeat(64),
    'observed',
    [],
    '٢٠٢٦-٠٨-٢٣T٠٠:٠٠:٠٠Z',
  ),
  'timestamp digits must be ASCII',
);

const profileBase = {
  schema: 'third-party-node-profile/1',
  governance_model: 'local',
  qsol_governance_adopted: false,
  nexus_required: false,
  council_required: false,
};
validateThirdPartyProfile({ ...profileBase, implementation: '🛰'.repeat(128) });
mustReject(
  () => validateThirdPartyProfile({ ...profileBase, implementation: '🛰'.repeat(129) }),
  'profile maxLength counts Unicode scalar values',
);

console.log('phase6 javascript sdk adversarial regressions OK');
