import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  BinaryAnalysisResult,
  BinaryMetadata,
  AnalysisOptions,
} from '../types.js';
import { analyzeNativeBinary } from './native.js';
import { analyzeElectronTarget } from './electron.js';
import { inspectBinaryFormat } from '../detector.js';

export async function analyzeMacOSApp(
  appPath: string,
  options: AnalysisOptions = {}
): Promise<BinaryAnalysisResult> {
  const contentsDir = path.join(appPath, 'Contents');
  const macosDir = path.join(contentsDir, 'MacOS');
  const plistPath = path.join(contentsDir, 'Info.plist');
  const asarPath = path.join(contentsDir, 'Resources', 'app.asar');

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

  // 3. If purely native Cocoa / Mach-O application
  if (nativeBinaryPath && fs.existsSync(nativeBinaryPath)) {
    const nativeRes = await analyzeNativeBinary(nativeBinaryPath, options);
    nativeRes.metadata.fileName = path.basename(appPath, '.app');
    nativeRes.metadata.filePath = appPath;
    nativeRes.metadata.format = 'macos_app';
    return nativeRes;
  }

  throw new Error(`Unable to find executable binary inside macOS app bundle at ${appPath}`);
}
