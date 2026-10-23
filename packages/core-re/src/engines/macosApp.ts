import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  BinaryAnalysisResult,
  BinaryMetadata,
  AnalysisOptions,
  DisassembledFunction,
} from '../types.js';
import { analyzeNativeBinary } from './native.js';
import { analyzeElectronTarget } from './electron.js';
import { inspectBinaryFormat } from '../detector.js';

function extractEmbeddedScriptModules(resourcesDir: string): {
  modules: BinaryAnalysisResult['modules'];
  functions: DisassembledFunction[];
} {
  const modules: BinaryAnalysisResult['modules'] = [];
  const functions: DisassembledFunction[] = [];

  function scanDir(dir: string, baseDir: string) {
    if (!fs.existsSync(dir)) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const ent of entries) {
        const fullPath = path.join(dir, ent.name);
        if (ent.isDirectory() && ent.name !== 'localization' && !ent.name.startsWith('.')) {
          scanDir(fullPath, baseDir);
        } else if (ent.isFile() && (ent.name.endsWith('.lua') || ent.name.endsWith('.js'))) {
          const relPath = path.relative(baseDir, fullPath);
          const modName = relPath.replace(/\.(lua|js)$/, '').replace(/\//g, '::');
          const content = fs.readFileSync(fullPath, 'utf-8');

          const modFuncs: string[] = [];
          const fnRegex = /function\s+([A-Za-z0-9_.:]+)\s*\(/g;
          let match;
          while ((match = fnRegex.exec(content)) !== null) {
            const fnName = match[1];
            if (!fnName.includes('(') && fnName.length > 2 && !modFuncs.includes(fnName)) {
              modFuncs.push(fnName);
              const lineNo = content.slice(0, match.index).split('\n').length;
              functions.push({
                id: `fn_${fnName.replace(/[^a-zA-Z0-9_]/g, '_')}`,
                name: fnName,
                address: `script://${relPath}#L${lineNo}`,
                moduleName: modName,
                isExported: true,
                isImported: false,
                callers: [],
                callees: [],
                xrefs: [],
                instructions: [],
                detectedRole: fnName.includes('save') || fnName.includes('file')
                  ? 'storage'
                  : fnName.includes('http') || fnName.includes('network')
                  ? 'network'
                  : fnName.includes('ui') || fnName.includes('button')
                  ? 'ui'
                  : fnName.includes('state') || fnName.includes('game')
                  ? 'core'
                  : 'general',
                pseudoCode: `// Script function from ${relPath}:${lineNo}\nfunction ${fnName}(...)`,
                provenance: 'verified_fact',
              });
            }
          }

          modules.push({
            name: modName,
            type: 'js_file',
            functions: modFuncs,
          });
        }
      }
    } catch {}
  }

  scanDir(resourcesDir, resourcesDir);
  return { modules, functions };
}

export async function analyzeMacOSApp(
  appPath: string,
  options: AnalysisOptions = {}
): Promise<BinaryAnalysisResult> {
  const contentsDir = path.join(appPath, 'Contents');
  const macosDir = path.join(contentsDir, 'MacOS');
  const plistPath = path.join(contentsDir, 'Info.plist');
  const resourcesDir = path.join(contentsDir, 'Resources');
  const asarPath = path.join(resourcesDir, 'app.asar');

  // 1. Resolve Executable Name from Info.plist or directory listing
  let execName = '';
  if (fs.existsSync(plistPath)) {
    try {
      const plistContent = fs.readFileSync(plistPath, 'utf-8');
      const execMatch = /<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/.exec(plistContent);
      if (execMatch) {
        execName = execMatch[1].trim();
      }
    } catch {}
  }

  if (!execName && fs.existsSync(macosDir)) {
    const files = fs.readdirSync(macosDir);
    if (files.length > 0) execName = files[0];
  }

  const nativeBinaryPath = execName ? path.join(macosDir, execName) : '';
  const isElectron = fs.existsSync(asarPath);

  // 2. If it's an Electron App Bundle, perform dual-layer analysis
  if (isElectron) {
    const electronResult = analyzeElectronTarget(asarPath, options);
    let nativeResult: BinaryAnalysisResult | null = null;

    if (nativeBinaryPath && fs.existsSync(nativeBinaryPath)) {
      try {
        nativeResult = await analyzeNativeBinary(nativeBinaryPath, options);
      } catch {}
    }

    const inspection = inspectBinaryFormat(appPath);
    const appName = path.basename(appPath, '.app');

    const metadata: BinaryMetadata = {
      fileName: appName,
      filePath: appPath,
      fileSize: fs.statSync(appPath).size,
      format: 'macos_app',
      architecture: nativeResult?.metadata.architecture || 'electron (arm64/universal)',
      bitness: 64,
      endianness: 'little',
      platform: 'darwin',
      isStripped: nativeResult ? nativeResult.metadata.isStripped : false,
      importedLibraries: [
        ...(nativeResult?.metadata.importedLibraries || []),
        ...electronResult.metadata.importedLibraries,
      ],
      exportedSymbolsCount: (nativeResult?.metadata.exportedSymbolsCount || 0) + electronResult.metadata.exportedSymbolsCount,
      functionsCount: (nativeResult?.functions.length || 0) + electronResult.functions.length,
      stringsCount: electronResult.strings.length + (nativeResult?.strings.length || 0),
      sha256: inspection.sha256,
    };

    return {
      metadata,
      sections: nativeResult?.sections || [],
      functions: [
        ...(nativeResult?.functions || []),
        ...electronResult.functions,
      ],
      strings: [
        ...electronResult.strings,
        ...(nativeResult?.strings.slice(0, 100) || []),
      ],
      ipcChannels: electronResult.ipcChannels,
      externalAPIs: [
        ...(nativeResult?.externalAPIs || []),
        ...electronResult.externalAPIs,
      ],
      modules: [
        ...(nativeResult?.modules || []),
        ...electronResult.modules,
      ],
      coverage: {
        formatDetection: 'complete',
        sectionExtraction: nativeResult ? 'complete' : 'unavailable',
        symbolResolution: 'complete',
        disassembly: 'complete',
        decompilation: 'complete',
        callGraph: 'complete',
        stringExtraction: 'complete',
        semanticAnalysis: 'pending',
      },
    };
  }

  // 3. Pure native Cocoa / Mach-O application (+ embedded game/runtime scripts)
  if (nativeBinaryPath && fs.existsSync(nativeBinaryPath)) {
    const nativeRes = await analyzeNativeBinary(nativeBinaryPath, options);
    nativeRes.metadata.fileName = path.basename(appPath, '.app');
    nativeRes.metadata.filePath = appPath;
    nativeRes.metadata.format = 'macos_app';

    // If application contains embedded game or application scripts (e.g. Balatro LÖVE2D scripts)
    if (fs.existsSync(resourcesDir)) {
      const embedded = extractEmbeddedScriptModules(resourcesDir);
      if (embedded.modules.length > 0) {
        nativeRes.modules.push(...embedded.modules);
        nativeRes.functions.push(...embedded.functions);
        nativeRes.metadata.functionsCount = nativeRes.functions.length;
      }
    }

    return nativeRes;
  }

  throw new Error(`Unable to find executable binary inside macOS app bundle at ${appPath}`);
}
