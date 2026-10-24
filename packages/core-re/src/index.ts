import type { BinaryAnalysisResult, AnalysisOptions } from './types.js';
import { detectBinaryFormat } from './detector.js';
import { analyzeNativeBinary } from './engines/native.js';
import { analyzeElectronTarget } from './engines/electron.js';
import { analyzeAndroidTarget } from './engines/android.js';
import { analyzeMacOSApp } from './engines/macosApp.js';

export * from './types.js';
export * from './detector.js';
export * from './strings.js';
export * from './utils/exec.js';
export * from './engines/macosApp.js';
export * from './engines/ghidra.js';
export * from './engines/electronSecurity.js';

export async function analyzeBinaryTarget(
  targetPath: string,
  options: AnalysisOptions = {}
): Promise<BinaryAnalysisResult> {
  const format = detectBinaryFormat(targetPath);

  switch (format) {
    case 'macos_app':
      return analyzeMacOSApp(targetPath, options);

    case 'electron_asar':
    case 'javascript_bundle':
      return analyzeElectronTarget(targetPath, options);

    case 'apk':
      return analyzeAndroidTarget(targetPath, options);

    case 'macho':
    case 'elf':
    case 'pe':
    case 'raw_binary':
    default:
      return analyzeNativeBinary(targetPath, options);
  }
}
