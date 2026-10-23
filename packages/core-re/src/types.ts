export type BinaryFormat =
  | 'macho'
  | 'elf'
  | 'pe'
  | 'electron_asar'
  | 'apk'
  | 'javascript_bundle'
  | 'macos_app'
  | 'raw_binary'
  | 'unknown';

export type ProvenanceKind = 'verified_fact' | 'heuristic_inference' | 'llm_hypothesis';

export interface Instruction {
  address: string;
  opcodeBytes: string;
  mnemonic: string;
  operands: string;
  targetAddress?: string;
  symbolStub?: string;
  isCall: boolean;
  isBranch: boolean;
  isReturn: boolean;
}

export interface BasicBlock {
  id: string;
  startAddress: string;
  endAddress: string;
  instructionsCount: number;
  successors: string[];
  predecessors: string[];
}

export interface Section {
  name: string;
  startAddress: string;
  size: number;
  rawOffset?: number;
  isExecutable: boolean;
  isWritable: boolean;
}

export interface AnalysisCoverage {
  formatDetection: 'complete' | 'partial' | 'failed';
  sectionExtraction: 'complete' | 'partial' | 'unavailable';
  symbolResolution: 'complete' | 'partial' | 'stripped';
  disassembly: 'complete' | 'partial' | 'unavailable';
  decompilation: 'complete' | 'partial' | 'unavailable';
  callGraph: 'complete' | 'partial' | 'unavailable';
  stringExtraction: 'complete' | 'partial' | 'unavailable';
  semanticAnalysis: 'complete' | 'pending' | 'unavailable';
}

export interface BinaryMetadata {
  fileName: string;
  filePath: string;
  fileSize: number;
  format: BinaryFormat;
  architecture: string;
  bitness: 32 | 64 | 'unknown';
  endianness: 'little' | 'big' | 'unknown';
  platform: string;
  entrypoint?: string;
  isStripped: boolean;
  importedLibraries: string[];
  exportedSymbolsCount: number;
  functionsCount: number;
  stringsCount: number;
  sha256: string;
}

export interface DisassembledFunction {
  id: string;
  address: string;
  name: string;
  mangledName?: string;
  moduleName?: string;
  size?: number;
  isExported: boolean;
  isImported: boolean;
  callers: string[];
  callees: string[];
  xrefs: string[];
  instructions: Instruction[];
  basicBlocks?: BasicBlock[];
  pseudoCode?: string;
  detectedRole?: string;
  provenance: ProvenanceKind;
}

export interface ExtractedString {
  value: string;
  offset?: number;
  classification: 'url' | 'filepath' | 'key_or_token' | 'sql' | 'error_message' | 'general';
  associatedFunction?: string;
}

export interface IPCChannel {
  name: string;
  pattern: 'send' | 'invoke' | 'handle' | 'on' | 'postMessage';
  sourceFile: string;
  sender?: string;
  handler?: string;
  payloadType?: string;
}

export interface ExternalAPI {
  name: string;
  library: string;
  type: 'c_runtime' | 'system_syscall' | 'framework' | 'web_api' | 'node_internal';
  occurrences: number;
}

export interface BinaryAnalysisResult {
  metadata: BinaryMetadata;
  sections: Section[];
  functions: DisassembledFunction[];
  strings: ExtractedString[];
  ipcChannels: IPCChannel[];
  externalAPIs: ExternalAPI[];
  modules: {
    name: string;
    type: 'native_lib' | 'js_file' | 'dex_class' | 'section';
    size?: number;
    functions: string[];
  }[];
  coverage: AnalysisCoverage;
}

export interface AnalysisOptions {
  extractStrings?: boolean;
  maxFunctions?: number;
  maxDisassemblyLines?: number;
  decompile?: boolean;
  deepTrace?: boolean;
}
