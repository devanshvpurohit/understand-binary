import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  BinaryInspectionTools,
  scanSecurityFindings,
  BinaryInvestigator,
} from '../dist/index.js';
import type { ArchitectureIR } from '@understand-binary/bridge';

const createSampleIR = (): ArchitectureIR => ({
  targetInfo: {
    fileName: 'sample_service',
    filePath: '/bin/sample_service',
    fileSize: 8192,
    format: 'macho',
    arch: 'arm64',
    bitness: 64,
    endianness: 'little',
    platform: 'darwin',
    isStripped: false,
    sha256: 'fedcba654321',
  },
  sections: [],
  subsystems: [
    {
      id: 'core_sub',
      name: 'Core Subsystem',
      description: 'Core logic',
      role: 'core',
      componentIds: ['comp_main'],
    },
  ],
  components: [
    {
      id: 'comp_main',
      name: 'MainModule',
      subsystemId: 'core_sub',
      type: 'module',
      symbolIds: ['fn_main', 'fn_step1', 'fn_step2', 'fn_danger'],
    },
  ],
  symbols: [
    {
      id: 'fn_main',
      name: 'main_entry',
      componentId: 'comp_main',
      address: '0x1000',
      isExported: true,
      isImported: false,
      role: 'core',
      callers: [],
      callees: ['fn_step1'],
      instructions: [
        {
          address: '0x1000',
          opcodeBytes: '94000002',
          mnemonic: 'bl',
          operands: '0x1008',
          targetAddress: '0x1008',
          symbolStub: 'fn_step1',
          isCall: true,
          isBranch: false,
          isReturn: false,
        },
        {
          address: '0x1004',
          opcodeBytes: 'd65f03c0',
          mnemonic: 'ret',
          operands: '',
          isCall: false,
          isBranch: false,
          isReturn: true,
        },
      ],
      provenance: 'verified_fact',
    },
    {
      id: 'fn_step1',
      name: 'dispatch_pipeline',
      componentId: 'comp_main',
      address: '0x1008',
      isExported: false,
      isImported: false,
      role: 'core',
      callers: ['fn_main'],
      callees: ['fn_danger'],
      instructions: [],
      provenance: 'verified_fact',
    },
    {
      id: 'fn_danger',
      name: 'system',
      componentId: 'comp_main',
      address: '0x2000',
      isExported: false,
      isImported: true,
      role: 'core',
      callers: ['fn_step1'],
      callees: [],
      instructions: [],
      provenance: 'verified_fact',
    },
  ],
  relationships: [
    { sourceId: 'fn_main', targetId: 'fn_step1', type: 'calls', confidence: 1, provenance: 'verified_fact' },
    { sourceId: 'fn_step1', targetId: 'fn_danger', type: 'calls', confidence: 1, provenance: 'verified_fact' },
  ],
  strings: [
    { value: 'http://insecure-api.internal/telemetry', classification: 'url' },
    { value: 'api_key = "secret_1234567890"', classification: 'key_or_token' },
  ],
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
});

test('Security Findings Scanner: Detects command injection, cleartext HTTP, and hardcoded secrets', () => {
  const ir = createSampleIR();
  const findings = scanSecurityFindings(ir);

  assert.ok(findings.some((f) => f.category === 'command_injection'));
  assert.ok(findings.some((f) => f.category === 'weak_cryptography'));
  assert.ok(findings.some((f) => f.category === 'hardcoded_secrets'));
});

test('Inspection Tools: Traces static execution call path using BFS', () => {
  const ir = createSampleIR();
  const tools = new BinaryInspectionTools(ir);

  const pathResult = tools.findCallPath('main_entry', 'system');
  assert.equal(pathResult.found, true);
  assert.equal(pathResult.pathLength, 3);
  assert.equal(pathResult.path![0].name, 'main_entry');
  assert.equal(pathResult.path![1].name, 'dispatch_pipeline');
  assert.equal(pathResult.path![2].name, 'system');
});

test('Binary Investigator: Executes evidence-backed investigation without hallucination', async () => {
  const ir = createSampleIR();
  const investigator = new BinaryInvestigator(ir);

  const res = await investigator.investigate('Where are secrets or command execution APIs called?');
  assert.ok(res.provenFacts.length > 0);
  assert.ok(res.evidenceCitations.length > 0);
  assert.ok(res.toolCallsExecuted.length > 0);
});
