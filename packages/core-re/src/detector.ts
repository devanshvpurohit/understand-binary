import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { BinaryFormat } from './types.js';

export interface FormatInspection {
  format: BinaryFormat;
  architecture: string;
  bitness: 32 | 64 | 'unknown';
  endianness: 'little' | 'big' | 'unknown';
  sha256: string;
  fileSize: number;
}

export function inspectBinaryFormat(filePath: string): FormatInspection {
  if (!fs.existsSync(filePath)) {
    return {
      format: 'unknown',
      architecture: 'unknown',
      bitness: 'unknown',
      endianness: 'unknown',
      sha256: '',
      fileSize: 0,
    };
  }

  const stat = fs.statSync(filePath);
  const ext = path.extname(filePath).toLowerCase();

  // If directory
  if (stat.isDirectory()) {
    if (ext === '.app' || fs.existsSync(path.join(filePath, 'Contents'))) {
      const asarPath = path.join(filePath, 'Contents', 'Resources', 'app.asar');
      const macosDir = path.join(filePath, 'Contents', 'MacOS');
      let arch = 'arm64';
      let sha256 = '';

      if (fs.existsSync(macosDir)) {
        const files = fs.readdirSync(macosDir);
        if (files.length > 0) {
          const mainBin = path.join(macosDir, files[0]);
          if (fs.existsSync(mainBin) && !fs.statSync(mainBin).isDirectory()) {
            const binBuf = fs.readFileSync(mainBin);
            sha256 = crypto.createHash('sha256').update(binBuf).digest('hex');
          }
        }
      }

      return {
        format: 'macos_app',
        architecture: fs.existsSync(asarPath) ? 'electron (macos bundle)' : arch,
        bitness: 64,
        endianness: 'little',
        sha256: sha256 || crypto.createHash('sha256').update(filePath).digest('hex'),
        fileSize: stat.size,
      };
    }

    return {
      format: fs.existsSync(path.join(filePath, 'package.json')) ? 'javascript_bundle' : 'unknown',
      architecture: 'all',
      bitness: 'unknown',
      endianness: 'unknown',
      sha256: '',
      fileSize: 0,
    };
  }

  // Calculate SHA-256
  const fileBuffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  if (ext === '.asar') {
    return {
      format: 'electron_asar',
      architecture: 'all',
      bitness: 'unknown',
      endianness: 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  if (ext === '.apk') {
    return {
      format: 'apk',
      architecture: 'dalvik/multi-arch',
      bitness: 'unknown',
      endianness: 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    return {
      format: 'javascript_bundle',
      architecture: 'javascript-vm',
      bitness: 'unknown',
      endianness: 'unknown',
      sha256,
      fileSize: stat.size,
    };
  }

  if (fileBuffer.length < 16) {
    return {
      format: 'raw_binary',
      architecture: 'unknown',
      bitness: 'unknown',
      endianness: 'unknown',
      sha256,
      fileSize: stat.size,
    };
  }

  // Mach-O Magic Numbers:
  // 0xfeedface = 32-bit BE, 0xcefaedfe = 32-bit LE
  // 0xfeedfacf = 64-bit BE, 0xcffaedfe = 64-bit LE
  // 0xcafebabe = FAT binary BE, 0xbebafeca = FAT binary LE
  const magicBE = fileBuffer.readUInt32BE(0);
  const magicLE = fileBuffer.readUInt32LE(0);

  if (magicBE === 0xfeedface || magicLE === 0xfeedface) {
    return {
      format: 'macho',
      architecture: 'x86_or_arm',
      bitness: 32,
      endianness: magicBE === 0xfeedface ? 'big' : 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  if (magicBE === 0xfeedfacf || magicLE === 0xfeedfacf) {
    // Check CPU type at offset 4
    const isLittle = magicLE === 0xfeedfacf;
    const cpuType = isLittle ? fileBuffer.readInt32LE(4) : fileBuffer.readInt32BE(4);
    // 0x01000007 = CPU_TYPE_X86_64, 0x0100000c = CPU_TYPE_ARM64
    const arch = cpuType === 0x0100000c ? 'arm64' : cpuType === 0x01000007 ? 'x86_64' : '64-bit-native';

    return {
      format: 'macho',
      architecture: arch,
      bitness: 64,
      endianness: isLittle ? 'little' : 'big',
      sha256,
      fileSize: stat.size,
    };
  }

  if (magicBE === 0xcafebabe || magicLE === 0xcafebabe) {
    // Could be Mach-O Universal FAT or Java Class
    // Java class magic is 0xCAFEBABE, followed by minor_version (u2), major_version (u2)
    // If major version is 45..65, it's Java Class
    const minor = fileBuffer.readUInt16BE(4);
    const major = fileBuffer.readUInt16BE(6);
    if (major >= 45 && major <= 70) {
      return {
        format: 'raw_binary',
        architecture: 'jvm-bytecode',
        bitness: 'unknown',
        endianness: 'big',
        sha256,
        fileSize: stat.size,
      };
    }
    return {
      format: 'macho',
      architecture: 'universal-fat (arm64/x86_64)',
      bitness: 64,
      endianness: magicBE === 0xcafebabe ? 'big' : 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  // ELF: 0x7F 'E' 'L' 'F'
  if (fileBuffer[0] === 0x7f && fileBuffer[1] === 0x45 && fileBuffer[2] === 0x4c && fileBuffer[3] === 0x46) {
    const bitness = fileBuffer[4] === 2 ? 64 : fileBuffer[4] === 1 ? 32 : 'unknown';
    const endianness = fileBuffer[5] === 1 ? 'little' : fileBuffer[5] === 2 ? 'big' : 'unknown';
    const e_machine = endianness === 'little' ? fileBuffer.readUInt16LE(18) : fileBuffer.readUInt16BE(18);

    let arch = 'unknown';
    if (e_machine === 0x03) arch = 'x86';
    else if (e_machine === 0x3e) arch = 'x86_64';
    else if (e_machine === 0x28) arch = 'arm';
    else if (e_machine === 0xb7) arch = 'arm64';
    else if (e_machine === 0xf3) arch = 'riscv';

    return {
      format: 'elf',
      architecture: arch,
      bitness,
      endianness,
      sha256,
      fileSize: stat.size,
    };
  }

  // PE: 'MZ'
  if (fileBuffer[0] === 0x4d && fileBuffer[1] === 0x5a) {
    return {
      format: 'pe',
      architecture: 'x86_or_x64',
      bitness: 64,
      endianness: 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  // ZIP / APK: 'PK\x03\x04'
  if (fileBuffer[0] === 0x50 && fileBuffer[1] === 0x4b && fileBuffer[2] === 0x03 && fileBuffer[3] === 0x04) {
    return {
      format: ext === '.apk' ? 'apk' : 'raw_binary',
      architecture: 'archive/zip',
      bitness: 'unknown',
      endianness: 'little',
      sha256,
      fileSize: stat.size,
    };
  }

  return {
    format: 'raw_binary',
    architecture: 'unknown',
    bitness: 'unknown',
    endianness: 'unknown',
    sha256,
    fileSize: stat.size,
  };
}

export function detectBinaryFormat(filePath: string): BinaryFormat {
  return inspectBinaryFormat(filePath).format;
}
