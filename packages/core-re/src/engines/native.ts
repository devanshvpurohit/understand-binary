import * as path from 'node:path';
import type {
  BinaryAnalysisResult,
  BinaryMetadata,
  DisassembledFunction,
  ExternalAPI,
  Instruction,
  Section,
  AnalysisCoverage,
  AnalysisOptions,
} from '../types.js';
import { safeExec } from '../utils/exec.js';
import { extractStringsFromFile } from '../strings.js';
import { inspectBinaryFormat } from '../detector.js';

export async function analyzeNativeBinary(
  filePath: string,
  options: AnalysisOptions = {}
): Promise<BinaryAnalysisResult> {
  const fileName = path.basename(filePath);
  const inspection = inspectBinaryFormat(filePath);

  const importedLibraries: string[] = [];
  const sections: Section[] = [];
  const functions: DisassembledFunction[] = [];
  const externalAPIs: ExternalAPI[] = [];
  const modulesMap = new Map<string, string[]>();

  let disassemblyCoverage: AnalysisCoverage['disassembly'] = 'unavailable';
  let symbolCoverage: AnalysisCoverage['symbolResolution'] = 'stripped';
  let callGraphCoverage: AnalysisCoverage['callGraph'] = 'unavailable';
  let sectionCoverage: AnalysisCoverage['sectionExtraction'] = 'unavailable';

  // 1. Extract Dynamic Libraries safely
  if (process.platform === 'darwin') {
    const otoolRes = await safeExec('/usr/bin/otool', ['-L', filePath]);
    if (otoolRes.success) {
      for (const line of otoolRes.stdout.split('\n').slice(1)) {
        const trimmed = line.trim();
        if (trimmed) {
          const libName = trimmed.split(' ')[0];
          if (libName && !importedLibraries.includes(libName)) {
            importedLibraries.push(libName);
          }
        }
      }
    }
  } else {
    const objdumpRes = await safeExec('objdump', ['-p', filePath]);
    if (objdumpRes.success) {
      for (const line of objdumpRes.stdout.split('\n')) {
        const match = /NEEDED\s+(.+)/.exec(line);
        if (match && match[1]) {
          const lib = match[1].trim();
          if (!importedLibraries.includes(lib)) importedLibraries.push(lib);
        }
      }
    }
  }

  // 2. Extract Sections
  if (process.platform === 'darwin') {
    const otoolSecRes = await safeExec('/usr/bin/otool', ['-l', filePath]);
    if (otoolSecRes.success) {
      sectionCoverage = 'complete';
      const lines = otoolSecRes.stdout.split('\n');
      let currSec = '';
      let currAddr = '';
      let currSize = 0;

      for (const line of lines) {
        const sectMatch = /sectname\s+(.+)/.exec(line);
        if (sectMatch) currSec = sectMatch[1].trim();
        const addrMatch = /addr\s+(0x[0-9a-fA-F]+)/.exec(line);
        if (addrMatch) currAddr = addrMatch[1];
        const sizeMatch = /size\s+(0x[0-9a-fA-F]+|[0-9]+)/.exec(line);
        if (sizeMatch && currSec) {
          currSize = sizeMatch[1].startsWith('0x') ? parseInt(sizeMatch[1], 16) : parseInt(sizeMatch[1], 10);
          sections.push({
            name: currSec,
            startAddress: currAddr,
            size: currSize,
            isExecutable: currSec.toLowerCase().includes('text'),
            isWritable: currSec.toLowerCase().includes('data'),
          });
          currSec = '';
        }
      }
    }
  }

  // 3. Extract Disassembly via otool -tv or objdump -d
  const rawInstructions: Instruction[] = [];
  let disasmOutput = '';

  if (process.platform === 'darwin') {
    const disasmRes = await safeExec('/usr/bin/otool', ['-tv', filePath], {
      maxBufferBytes: 30 * 1024 * 1024,
    });
    if (disasmRes.success && disasmRes.stdout.length > 50) {
      disasmOutput = disasmRes.stdout;
    }
  }

  if (!disasmOutput) {
    const objdumpRes = await safeExec('objdump', ['-d', filePath], {
      maxBufferBytes: 30 * 1024 * 1024,
    });
    if (objdumpRes.success && objdumpRes.stdout.length > 50) {
      disasmOutput = objdumpRes.stdout;
    }
  }

  // 4. Parse Instruction Stream & Call Targets
  if (disasmOutput) {
    disassemblyCoverage = 'complete';
    parseInstructionStream(disasmOutput, rawInstructions, options.maxDisassemblyLines ?? 5000);
  }

  // 5. Extract Defined & Imported Symbols via nm
  const knownSymbols = new Map<string, { address: string; type: string }>();
  const nmRes = await safeExec('/usr/bin/nm', ['-gjU', filePath]);
  if (nmRes.success && nmRes.stdout.trim()) {
    symbolCoverage = 'complete';
    for (const line of nmRes.stdout.split('\n')) {
      const sym = line.trim().replace(/^_+/, '');
      if (sym) {
        knownSymbols.set(sym, { address: '', type: 'T' });
      }
    }
  }

  // 6. Partition Instructions into Functions & Build Call Graph
  if (rawInstructions.length > 0) {
    partitionInstructionsIntoFunctions(
      rawInstructions,
      knownSymbols,
      functions,
      modulesMap,
      options.maxFunctions ?? 150
    );
    callGraphCoverage = 'complete';
  } else if (knownSymbols.size > 0) {
    // If disassembly failed, populate functions from symbol table
    symbolCoverage = 'partial';
    for (const [symName] of knownSymbols.entries()) {
      const role = detectRoleFromName(symName);
      functions.push({
        id: `sym_${symName}`,
        address: 'N/A',
        name: symName,
        isExported: true,
        isImported: false,
        callers: [],
        callees: [],
        xrefs: [],
        instructions: [],
        detectedRole: role,
        provenance: 'verified_fact',
      });
      if (!modulesMap.has('MainBinary')) modulesMap.set('MainBinary', []);
      modulesMap.get('MainBinary')!.push(`sym_${symName}`);
    }
  }

  // 7. Resolve External APIs from Imported Symbols
  const nmUndefRes = await safeExec('/usr/bin/nm', ['-u', filePath]);
  if (nmUndefRes.success) {
    for (const line of nmUndefRes.stdout.split('\n')) {
      const cleanSym = line.trim().replace(/^_+/, '');
      if (cleanSym) {
        externalAPIs.push({
          name: cleanSym,
          library: importedLibraries[0] || 'libSystem.B.dylib',
          type: classifyAPIType(cleanSym),
          occurrences: 1,
        });
      }
    }
  }

  const strings = options.extractStrings !== false ? extractStringsFromFile(filePath) : [];

  const coverage: AnalysisCoverage = {
    formatDetection: 'complete',
    sectionExtraction: sectionCoverage,
    symbolResolution: symbolCoverage,
    disassembly: disassemblyCoverage,
    decompilation: 'unavailable',
    callGraph: callGraphCoverage,
    stringExtraction: strings.length > 0 ? 'complete' : 'unavailable',
    semanticAnalysis: 'pending',
  };

  const metadata: BinaryMetadata = {
    fileName,
    filePath,
    fileSize: inspection.fileSize,
    format: inspection.format,
    architecture: inspection.architecture,
    bitness: inspection.bitness,
    endianness: inspection.endianness,
    platform: process.platform,
    isStripped: functions.every((f) => !f.isExported && f.name.startsWith('sub_')),
    importedLibraries,
    exportedSymbolsCount: functions.filter((f) => f.isExported).length,
    functionsCount: functions.length,
    stringsCount: strings.length,
    sha256: inspection.sha256,
  };

  return {
    metadata,
    sections,
    functions,
    strings,
    ipcChannels: [],
    externalAPIs,
    modules: Array.from(modulesMap.entries()).map(([name, funcs]) => ({
      name,
      type: 'native_lib',
      functions: funcs,
    })),
    coverage,
  };
}

/** Parse raw text output from objdump or otool into structured Instruction objects */
function parseInstructionStream(output: string, instructions: Instruction[], maxLines: number) {
  const lines = output.split('\n');
  let count = 0;

  for (const line of lines) {
    if (count++ >= maxLines) break;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('/') || trimmed.startsWith('(')) continue;

    // Pattern 1 (ARM64 otool): 0000000100000700	add	x0, x0, #0x68
    // Pattern 2 (x86_64 objdump): 100000718:	55	pushq	%rbp
    // Pattern 3 with symbol stub: 100000725:	e9 59 3c 00 00	jmp	0x100004383 ## symbol stub for: _strcoll
    const match = /^(?:0x)?([0-9a-fA-F]+)[:\t]\s*([0-9a-fA-F\s]{2,16})?\t*([a-zA-Z._]+)\s*(.*)$/.exec(trimmed);
    if (!match) continue;

    const [, addrStr, opcodes, mnemonic, rest] = match;
    const addr = addrStr.startsWith('0x') ? addrStr : `0x${addrStr}`;

    let operands = rest || '';
    let symbolStub: string | undefined;
    let targetAddress: string | undefined;

    // Detect symbol stubs: '## symbol stub for: _strcoll' or '; symbol stub for: _strcoll'
    const stubMatch = /(?:##|;)\s*symbol stub for:\s*(_?[a-zA-Z0-9_$]+)/.exec(operands);
    if (stubMatch) {
      symbolStub = stubMatch[1].replace(/^_+/, '');
      operands = operands.replace(stubMatch[0], '').trim();
    }

    // Detect target address in operands: '0x100004383' or '#0x10000...'
    const targetMatch = /(?:0x|#0x)([0-9a-fA-F]{6,16})/.exec(operands);
    if (targetMatch) {
      targetAddress = `0x${targetMatch[1]}`;
    }

    const m = mnemonic.toLowerCase();
    const isCall = m.startsWith('call') || m === 'bl' || m === 'blr';
    const isBranch = m.startsWith('j') || m.startsWith('b') || m.startsWith('b.');
    const isReturn = m === 'ret' || m === 'retq';

    instructions.push({
      address: addr,
      opcodeBytes: (opcodes || '').trim(),
      mnemonic: m,
      operands: operands.trim(),
      targetAddress,
      symbolStub,
      isCall,
      isBranch,
      isReturn,
    });
  }
}

/** Group linear instruction stream into candidate functions and extract verified callers/callees */
function partitionInstructionsIntoFunctions(
  instructions: Instruction[],
  knownSymbols: Map<string, { address: string; type: string }>,
  functions: DisassembledFunction[],
  modulesMap: Map<string, string[]>,
  maxFunctions: number
) {
  const funcList: DisassembledFunction[] = [];
  let currentInstructions: Instruction[] = [];
  let funcStartAddr = instructions[0]?.address || '0x0';
  let funcIndex = 1;

  const commitFunction = () => {
    if (currentInstructions.length === 0) return;
    const firstInst = currentInstructions[0];
    const funcName = funcIndex === 1 ? 'main_entry' : `sub_${firstInst.address.replace('0x', '')}`;
    const role = detectRoleFromName(funcName);

    // Extract Callees from call instructions
    const callees: string[] = [];
    for (const inst of currentInstructions) {
      if (inst.isCall || (inst.isBranch && inst.symbolStub)) {
        const callee = inst.symbolStub || inst.targetAddress;
        if (callee && !callees.includes(callee)) {
          callees.push(callee);
        }
      }
    }

    funcList.push({
      id: `fn_${firstInst.address}`,
      address: firstInst.address,
      name: funcName,
      isExported: funcIndex === 1,
      isImported: false,
      callers: [],
      callees,
      xrefs: [],
      instructions: currentInstructions,
      size: currentInstructions.length * 4,
      detectedRole: role,
      provenance: 'verified_fact',
    });

    currentInstructions = [];
    funcIndex++;
  };

  for (let i = 0; i < instructions.length && funcList.length < maxFunctions; i++) {
    const inst = instructions[i];
    currentInstructions.push(inst);

    // Boundary indicator: return instruction marks end of function block
    if (inst.isReturn) {
      commitFunction();
    }
  }

  // Commit remaining instructions
  if (currentInstructions.length > 0 && funcList.length < maxFunctions) {
    commitFunction();
  }

  // Cross-reference: compute verified callers from callees
  const funcAddrMap = new Map<string, DisassembledFunction>();
  const funcNameMap = new Map<string, DisassembledFunction>();
  for (const f of funcList) {
    funcAddrMap.set(f.address.toLowerCase(), f);
    funcNameMap.set(f.name.toLowerCase(), f);
  }

  for (const caller of funcList) {
    for (const target of caller.callees) {
      const targetLower = target.toLowerCase();
      const targetFunc = funcAddrMap.get(targetLower) || funcNameMap.get(targetLower);
      if (targetFunc && !targetFunc.callers.includes(caller.id)) {
        targetFunc.callers.push(caller.id);
        targetFunc.xrefs.push(caller.address);
      }
    }
  }

  for (const f of funcList) {
    functions.push(f);
    const mod = 'MainExecutable';
    if (!modulesMap.has(mod)) modulesMap.set(mod, []);
    modulesMap.get(mod)!.push(f.id);
  }
}

function detectRoleFromName(name: string): string {
  const lower = name.toLowerCase();
  if (lower.includes('crypt') || lower.includes('aes') || lower.includes('sha') || lower.includes('rsa') || lower.includes('ssl')) return 'cryptography';
  if (lower.includes('socket') || lower.includes('http') || lower.includes('net') || lower.includes('connect') || lower.includes('recv') || lower.includes('send')) return 'network';
  if (lower.includes('sql') || lower.includes('db') || lower.includes('store') || lower.includes('cache') || lower.includes('file') || lower.includes('read') || lower.includes('write')) return 'storage';
  if (lower.includes('ui') || lower.includes('window') || lower.includes('view') || lower.includes('render') || lower.includes('draw')) return 'ui';
  if (lower.includes('auth') || lower.includes('login') || lower.includes('token') || lower.includes('permission')) return 'auth';
  if (lower.includes('ipc') || lower.includes('pipe') || lower.includes('message')) return 'ipc';
  return 'core';
}

function classifyAPIType(name: string): ExternalAPI['type'] {
  const lower = name.toLowerCase();
  if (lower.startsWith('pthread_') || lower.startsWith('malloc') || lower.startsWith('free') || lower.startsWith('memcpy')) return 'c_runtime';
  if (lower.startsWith('open') || lower.startsWith('read') || lower.startsWith('write') || lower.startsWith('close') || lower.startsWith('ioctl')) return 'system_syscall';
  return 'framework';
}
