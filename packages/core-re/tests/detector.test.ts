import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { inspectBinaryFormat, detectBinaryFormat } from '../dist/detector.js';

test('Format Detector: Inspects Mach-O universal binary correctly', () => {
  const inspection = inspectBinaryFormat('/bin/ls');
  assert.equal(inspection.format, 'macho');
  assert.ok(inspection.sha256.length === 64, 'SHA256 hash must be 64 characters');
  assert.ok(inspection.fileSize > 0, 'File size must be greater than 0');
  assert.equal(detectBinaryFormat('/bin/ls'), 'macho');
});

test('Format Detector: Handles non-existent files gracefully', () => {
  const inspection = inspectBinaryFormat('/tmp/definitely_not_a_real_binary_12345');
  assert.equal(inspection.format, 'unknown');
  assert.equal(inspection.fileSize, 0);
});
