/**
 * VeriRespond Canonical JSON Serialization
 * Per PROTOCOL_AND_CONTRACTS.md:
 * - Deterministic UTF-8 JSON representation
 * - Sorted keys recursively
 * - No insignificant whitespace (no spaces around : or ,)
 * - Strict type handling (no NaN/Infinity)
 */

function canonicalize(val) {
  if (val === null || typeof val === 'boolean' || typeof val === 'number' || typeof val === 'string') {
    if (typeof val === 'number' && (!Number.isFinite(val) || Number.isNaN(val))) {
      throw new Error('NaN and Infinity are not allowed in canonical JSON');
    }
    return JSON.stringify(val);
  }

  if (Array.isArray(val)) {
    return '[' + val.map(canonicalize).join(',') + ']';
  }

  if (typeof val === 'object') {
    const keys = Object.keys(val).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + canonicalize(val[k]));
    return '{' + parts.join(',') + '}';
  }

  throw new Error(`Unsupported type for canonical JSON: ${typeof val}`);
}

module.exports = { canonicalize };
