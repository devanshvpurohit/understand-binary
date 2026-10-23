import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { isNoiseSymbol } from '../dist/filter.js';
import { normalizeBinaryAnalysis } from '../dist/normalizer.js';
import type { BinaryAnalysisResult } from '@understand-binary/core-re';

test('Noise Filter: Identifies compiler intrinsics and trampolines', () => {
  assert.equal(isNoiseSymbol('_start'), true);
  assert.equal(isNoiseSymbol('dyld_stub_binder'), true);
  assert.equal(isNoiseSymbol('__libc_csu_init'), true);
  assert.equal(isNoiseSymbol('handle_network_packet'), false);
});

test('Normalizer: Normalizes BinaryAnalysisResult into ArchitectureIR', () => {
  const mockResult: BinaryAnalysisResult = {
    metadata: {
      fileName: 'test_app',
      filePath: '/path/test_app',
      fileSize: 1024,
      format: 'elf',
      architecture: 'x86_64',
      bitness: 64,
      endianness: 'little',
      platform: 'linux',
      isStripped: false,
      importedLibraries: ['libc.so.6'],
      exportedSymbolsCount: 1,
      functionsCount: 2,
      stringsCount: 1,
      sha256: 'abcdef123456',
    },
    sections: [],
    functions: [
      {
        id: 'fn_1',
        address: '0x1000',
        name: 'crypto_encrypt_data',
        isExported: true,
        isImported: false,
        callers: [],
        callees: ['fn_2'],
        xrefs: [],
        instructions: [],
        detectedRole: 'cryptography',
        provenance: 'verified_fact',
      },
      {
        id: 'fn_2',
        address: '0x2000',
        name: 'aes_cipher_block',
        isExported: false,
        isImported: false,
        callers: ['fn_1'],
        callees: [],
        xrefs: ['0x1000'],
        instructions: [],
        detectedRole: 'cryptography',
        provenance: 'verified_fact',
      },
    ],
    strings: [{ value: 'https://auth.server.com', classification: 'url' }],
    ipcChannels: [],
    externalAPIs: [],
    modules: [{ name: 'Core', type: 'native_lib', functions: ['fn_1', 'fn_2'] }],
    coverage: {
      formatDetection: 'complete',
      sectionExtraction: 'complete',
      symbolResolution: 'complete',
      disassembly: 'complete',
      decompilation: 'unavailable',
      callGraph: 'complete',
      stringExtraction: 'complete',
      semanticAnalysis: 'pending',
    },
  };

  const ir = normalizeBinaryAnalysis(mockResult);
  assert.equal(ir.subsystems.length > 0, true);
  assert.ok(ir.subsystems.some((s) => s.role === 'security'));
  assert.equal(ir.symbols.length, 2);
  assert.equal(ir.relationships.length, 2); // 1 call relation + 1 import
});
