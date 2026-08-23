import fs from 'node:fs';
import { canonicalize, conformanceResult } from './qsol_fed_sdk.mjs';

const fixture = JSON.parse(fs.readFileSync(new URL('../../fixtures/phase6/conformance.json', import.meta.url), 'utf8'));
const result = conformanceResult(fixture);
process.stdout.write(canonicalize(result).toString('utf8') + '\n');
