export type BinaryFormat =
  | 'macho'
  | 'elf'
  | 'pe'
  | 'electron_asar'
  | 'apk'
  | 'javascript_bundle'
  | 'raw_binary'
  | 'unknown';

export interface BinaryMetadata {
  fileName: string;
  filePath: string;
  fileSize: number;
  format: BinaryFormat;
  architecture: string;
  platform: string;
  entrypoint?: string;
  isStripped: boolean;
  importedLibraries: string[];
  exportedSymbolsCount: number;
  functionsCount: number;
  stringsCount: number;
  sha256?: string;
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
  pseudoCode?: string;
  assemblySnippet?: string[];
  detectedRole?: string; // e.g., 'cryptography', 'network', 'auth', 'ui', 'storage', 'ipc'
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
}

export interface AnalysisOptions {
  extractStrings?: boolean;
  maxFunctions?: number;
  decompile?: boolean;
  deepTrace?: boolean;
}
