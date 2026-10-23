import * as fs from 'node:fs';
import * as path from 'node:path';
import type { BinaryFormat } from './types.js';

export function detectBinaryFormat(filePath: string): BinaryFormat {
  if (!fs.existsSync(filePath)) {
    return 'unknown';
  }

  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.asar') return 'electron_asar';
  if (ext === '.apk') return 'apk';
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') return 'javascript_bundle';

  const stat = fs.statSync(filePath);
  if (stat.isDirectory()) {
    if (fs.existsSync(path.join(filePath, 'package.json'))) {
      return 'javascript_bundle';
    }
    return 'unknown';
  }

  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.alloc(16);
  fs.readSync(fd, buffer, 0, 16, 0);
  fs.closeSync(fd);

  // Mach-O
  // 0xfeedface (32-bit BE), 0xcefaedfe (32-bit LE)
  // 0xfeedfacf (64-bit BE), 0xcffaedfe (64-bit LE)
  // 0xcafebabe (Universal Binary)
  const magic32 = buffer.readUInt32BE(0);
  const magic32LE = buffer.readUInt32LE(0);

  if (
    magic32 === 0xfeedface ||
    magic32LE === 0xfeedface ||
    magic32 === 0xfeedfacf ||
    magic32LE === 0xfeedfacf ||
    magic32 === 0xcafebabe
  ) {
    return 'macho';
  }

  // ELF: 0x7F 'E' 'L' 'F'
  if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
    return 'elf';
  }

  // PE: 'MZ'
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
    return 'pe';
  }

  // ZIP / APK: 'PK\x03\x04'
  if (buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
    if (ext === '.apk' || ext === '.jar' || ext === '.zip') {
      return 'apk';
    }
  }

  return 'raw_binary';
}
