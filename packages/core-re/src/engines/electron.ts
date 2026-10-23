import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  BinaryAnalysisResult,
  BinaryMetadata,
  DisassembledFunction,
  IPCChannel,
  ExternalAPI,
  AnalysisOptions,
} from '../types.js';
import { extractStringsFromBuffer } from '../strings.js';

export function analyzeElectronTarget(
  targetPath: string,
  options: AnalysisOptions = {}
): BinaryAnalysisResult {
  const stat = fs.statSync(targetPath);
  const fileName = path.basename(targetPath);
  const functions: DisassembledFunction[] = [];
  const ipcChannels: IPCChannel[] = [];
  const externalAPIs: ExternalAPI[] = [];
  const modulesMap = new Map<string, string[]>();

  // Collect JS files to analyze
  const jsFiles: { relPath: string; content: string }[] = [];

  if (stat.isDirectory()) {
    scanDirectoryForJS(targetPath, targetPath, jsFiles);
  } else if (targetPath.endsWith('.asar')) {
    // Basic ASAR reader or extraction
    readAsarOrFallback(targetPath, jsFiles);
  } else {
    // Single JS bundle file
    jsFiles.push({
      relPath: fileName,
      content: fs.readFileSync(targetPath, 'utf-8'),
    });
  }

  // Analyze each JS file
  for (const { relPath, content } of jsFiles) {
    const modName = relPath.replace(/\.[jt]sx?$/, '');
    if (!modulesMap.has(modName)) modulesMap.set(modName, []);

    // Detect IPC
    detectIPC(content, relPath, ipcChannels);

    // Detect function declarations / methods
    detectFunctions(content, modName, functions);

    // Detect external imports/APIs
    detectImports(content, externalAPIs);

    for (const f of functions.filter((fn) => fn.moduleName === modName)) {
      modulesMap.get(modName)!.push(f.id);
    }
  }

  const allText = jsFiles.map((f) => f.content).join('\n');
  const strings = options.extractStrings !== false ? extractStringsFromBuffer(Buffer.from(allText)) : [];

  const metadata: BinaryMetadata = {
    fileName,
    filePath: targetPath,
    fileSize: stat.size,
    format: 'electron_asar',
    architecture: 'all',
    platform: 'cross-platform',
    isStripped: false,
    importedLibraries: Array.from(new Set(externalAPIs.map((a) => a.library))),
    exportedSymbolsCount: functions.filter((f) => f.isExported).length,
    functionsCount: functions.length,
    stringsCount: strings.length,
  };

  return {
    metadata,
    functions,
    strings,
    ipcChannels,
    externalAPIs,
    modules: Array.from(modulesMap.entries()).map(([name, funcs]) => ({
      name,
      type: 'js_file',
      functions: funcs,
    })),
  };
}

function scanDirectoryForJS(rootDir: string, currentDir: string, results: { relPath: string; content: string }[]) {
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      scanDirectoryForJS(rootDir, full, results);
    } else if (/\.(js|mjs|cjs|ts|tsx)$/.test(entry.name)) {
      if (fs.statSync(full).size < 2 * 1024 * 1024) {
        results.push({
          relPath: path.relative(rootDir, full),
          content: fs.readFileSync(full, 'utf-8'),
        });
      }
    }
  }
}

function readAsarOrFallback(asarPath: string, results: { relPath: string; content: string }[]) {
  const buf = fs.readFileSync(asarPath);
  // ASAR format: [4 bytes uint32: 4][4 bytes uint32: header_size][4 bytes uint32: header_json_size][uint32: header_info_size][JSON header][raw files...]
  try {
    if (buf.length > 16) {
      const headerSize = buf.readUInt32LE(4);
      const jsonSize = buf.readUInt32LE(12);
      if (headerSize > 0 && jsonSize > 0 && jsonSize < buf.length) {
        const headerJson = buf.subarray(16, 16 + jsonSize).toString('utf-8');
        const header = JSON.parse(headerJson);
        // Traverse header files
        traverseAsarFiles(header.files, '', buf, 16 + jsonSize, results);
        return;
      }
    }
  } catch {
    // If structured parsing fails, fallback to extracting strings
  }

  // Fallback: analyze buffer as raw bundle
  results.push({
    relPath: 'app.asar.bundle.js',
    content: buf.toString('utf-8', 0, Math.min(buf.length, 500000)),
  });
}

function traverseAsarFiles(
  tree: any,
  prefix: string,
  fullBuf: Buffer,
  baseOffset: number,
  results: { relPath: string; content: string }[]
) {
  if (!tree) return;
  for (const [name, node] of Object.entries<any>(tree)) {
    const rel = prefix ? `${prefix}/${name}` : name;
    if (node.files) {
      traverseAsarFiles(node.files, rel, fullBuf, baseOffset, results);
    } else if (typeof node.offset === 'string' || typeof node.offset === 'number') {
      const offset = baseOffset + parseInt(node.offset, 10);
      const size = parseInt(node.size, 10);
      if (/\.(js|mjs|cjs|json)$/.test(name) && size < 1024 * 1024) {
        const fileContent = fullBuf.subarray(offset, offset + size).toString('utf-8');
        results.push({ relPath: rel, content: fileContent });
      }
    }
  }
}

function detectIPC(content: string, relPath: string, results: IPCChannel[]) {
  // ipcMain.handle('channel', ...)
  // ipcMain.on('channel', ...)
  // ipcRenderer.invoke('channel', ...)
  // ipcRenderer.send('channel', ...)
  const ipcRegex = /(?:ipcMain|ipcRenderer)\s*\.\s*(handle|on|send|invoke)\s*\(\s*['"`]([\w\-.:]+)['"`]/g;
  let match: RegExpExecArray | null;
  while ((match = ipcRegex.exec(content)) !== null) {
    const [, pattern, name] = match;
    results.push({
      name,
      pattern: pattern as any,
      sourceFile: relPath,
    });
  }
}

function detectFunctions(content: string, modName: string, results: DisassembledFunction[]) {
  // Named function declarations: function foo(...) {
  const fnRegex = /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(/g;
  let match: RegExpExecArray | null;
  let count = 0;
  while ((match = fnRegex.exec(content)) !== null && count < 50) {
    count++;
    const name = match[1];
    const isExported = match[0].startsWith('export');
    results.push({
      id: `${modName}::${name}`,
      address: `0x00_${name}`,
      name,
      moduleName: modName,
      isExported,
      isImported: false,
      callers: [],
      callees: [],
      xrefs: [],
      detectedRole: inferRole(name, content),
      pseudoCode: `function ${name}(...) { /* recovered function logic */ }`,
    });
  }

  // Class methods: methodName(...) {
  const methodRegex = /([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{/g;
  while ((match = methodRegex.exec(content)) !== null && count < 80) {
    const name = match[1];
    if (['if', 'for', 'while', 'switch', 'catch', 'function'].includes(name)) continue;
    count++;
    results.push({
      id: `${modName}::${name}`,
      address: `0x00_${name}`,
      name,
      moduleName: modName,
      isExported: false,
      isImported: false,
      callers: [],
      callees: [],
      xrefs: [],
      detectedRole: inferRole(name, content),
    });
  }
}

function detectImports(content: string, results: ExternalAPI[]) {
  // require('pkg') or import ... from 'pkg'
  const importRegex = /(?:require\s*\(\s*['"`]([@\w\-_/.]+)['"`]\)|from\s+['"`]([@\w\-_/.]+)['"`])/g;
  let match: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((match = importRegex.exec(content)) !== null) {
    const pkg = match[1] || match[2];
    if (pkg && !pkg.startsWith('.') && !seen.has(pkg)) {
      seen.add(pkg);
      results.push({
        name: pkg,
        library: pkg,
        type: pkg.startsWith('node:') || ['fs', 'path', 'crypto', 'http', 'child_process'].includes(pkg) ? 'node_internal' : 'web_api',
        occurrences: 1,
      });
    }
  }
}

function inferRole(fnName: string, code: string): string {
  const lower = fnName.toLowerCase();
  if (lower.includes('auth') || lower.includes('login') || lower.includes('token')) return 'auth';
  if (lower.includes('ipc') || lower.includes('message') || lower.includes('send') || lower.includes('recv')) return 'ipc';
  if (lower.includes('fetch') || lower.includes('request') || lower.includes('api') || lower.includes('download')) return 'network';
  if (lower.includes('save') || lower.includes('store') || lower.includes('load') || lower.includes('db')) return 'storage';
  if (lower.includes('render') || lower.includes('view') || lower.includes('ui') || lower.includes('modal')) return 'ui';
  return 'general';
}
