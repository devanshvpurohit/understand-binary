import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { extractStringsFromBuffer } from '../dist/strings.js';

test('String Extractor: Extracts URLs, SQL, and Keys from buffer', () => {
  const dummyPayload = Buffer.from(
    'Config https://api.example.com/v1/auth ' +
    'SELECT id, username FROM users WHERE active = 1; ' +
    'api_key = "ak_live_abcdef1234567890" ' +
    '/usr/local/bin/custom_daemon'
  );

  const extracted = extractStringsFromBuffer(dummyPayload);
  assert.ok(extracted.some((s) => s.classification === 'url' && s.value.includes('api.example.com')));
  assert.ok(extracted.some((s) => s.classification === 'sql' && s.value.includes('SELECT')));
  assert.ok(extracted.some((s) => s.classification === 'key_or_token'));
  assert.ok(extracted.some((s) => s.classification === 'filepath' && s.value.includes('/usr/local/bin')));
});
