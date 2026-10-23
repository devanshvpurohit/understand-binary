import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { synthesizeKnowledgeGraph } from '../dist/synthesizer.js';
import { KnowledgeGraphSchema } from '../dist/schema.js';
import type { ArchitectureIR } from '@understand-binary/bridge';

test('Synthesizer: Produces schema-valid KnowledgeGraph from ArchitectureIR', () => {
  const mockIR: ArchitectureIR = {
    targetInfo: {
      fileName: 'test.bin',
      filePath: '/path/test.bin',
      fileSize: 4096,
      format: 'elf',
      arch: 'x86_64',
      bitness: 64,
      endianness: 'little',
      platform: 'linux',
      isStripped: false,
      sha256: 'deadbeef1234',
    },
    sections: [],
    subsystems: [
      {
        id: 'sec_sub',
        name: 'Security Subsystem',
        description: 'Crypto and auth operations',
        role: 'security',
        componentIds: ['comp_sec'],
      },
    ],
    components: [
      {
        id: 'comp_sec',
        name: 'CryptoModule',
        subsystemId: 'sec_sub',
        type: 'module',
        symbolIds: ['fn_sha'],
      },
    ],
    symbols: [
      {
        id: 'fn_sha',
        name: 'sha256_hash',
        componentId: 'comp_sec',
        address: '0x4000',
        isExported: true,
        isImported: false,
        role: 'cryptography',
        callers: [],
        callees: [],
        provenance: 'verified_fact',
      },
    ],
    relationships: [],
    strings: [],
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

  const graph = synthesizeKnowledgeGraph(mockIR);
  const validated = KnowledgeGraphSchema.parse(graph);

  assert.equal(validated.project.name, 'test.bin');
  assert.equal(validated.nodes.length, 3); // 1 service + 1 module + 1 function
  assert.equal(validated.layers.length, 1);
  assert.ok(validated.tour.length > 0);
});
