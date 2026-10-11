// The launch copy quotes the guard's rule count (37: 30 shell rules and 7 MCP rules).
// If this fails, a rule was added or removed: update the count here and in every claim that quotes it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GUARD_RULES } from '../src/guardrules.js';

test('guard rule count matches the published claim', () => {
  const ids = [...GUARD_RULES];
  assert.equal(ids.filter((x) => x.startsWith('sh.')).length, 30);
  assert.equal(ids.filter((x) => x.startsWith('mcp.')).length, 7);
  assert.equal(ids.length, 37);
});
