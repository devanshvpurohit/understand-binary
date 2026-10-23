import type { ArchitectureIR } from '@understand-binary/bridge';

export interface SecurityFinding {
  id: string;
  category: 'unsafe_memory' | 'command_injection' | 'weak_cryptography' | 'hardcoded_secrets' | 'dangerous_ipc';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  affectedAddressOrFunction: string;
  supportingEvidence: string[];
  remediation: string;
}

const DANGEROUS_MEMORY_FUNCS = new Set([
  'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 'alloca', 'scanf'
]);

const COMMAND_EXEC_FUNCS = new Set([
  'system', 'popen', 'execve', 'execl', 'execlp', 'execle', 'execv', 'execvp'
]);

const WEAK_CRYPTO_PATTERNS = [
  'md5', 'sha1', 'des', 'rc4', 'blowfish'
];

export function scanSecurityFindings(ir: ArchitectureIR): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  let counter = 1;

  // 1. Scan Symbols and External APIs for Unsafe Memory & Command Execution
  for (const sym of ir.symbols) {
    const symLower = sym.name.toLowerCase();

    // Check Memory APIs
    if (DANGEROUS_MEMORY_FUNCS.has(symLower)) {
      findings.push({
        id: `SEC-${counter++}`,
        category: 'unsafe_memory',
        severity: 'high',
        confidence: 'high',
        title: `Unbounded memory function usage: '${sym.name}'`,
        description: `The binary imports or calls '${sym.name}', which does not check buffer boundaries and may lead to buffer overflow vulnerabilities.`,
        affectedAddressOrFunction: sym.address || sym.name,
        supportingEvidence: [
          `Symbol '${sym.name}' found at address ${sym.address || 'imported'}.`,
          `Callers: ${sym.callers.length > 0 ? sym.callers.slice(0, 3).join(', ') : 'unknown/stripped'}`
        ],
        remediation: `Replace '${sym.name}' with bounded variants such as strncpy, snprintf, or strlcpy.`,
      });
    }

    // Check Command Execution
    if (COMMAND_EXEC_FUNCS.has(symLower)) {
      findings.push({
        id: `SEC-${counter++}`,
        category: 'command_injection',
        severity: 'critical',
        confidence: 'high',
        title: `Shell / process execution primitive: '${sym.name}'`,
        description: `Direct invocation of system shell via '${sym.name}'. If user-controlled input reaches this call, it could allow arbitrary command execution.`,
        affectedAddressOrFunction: sym.address || sym.name,
        supportingEvidence: [
          `Process spawn symbol '${sym.name}' referenced at ${sym.address || 'imported'}.`,
        ],
        remediation: `Use safe exec APIs with parameter arrays instead of passing raw command strings to a shell.`,
      });
    }
  }

  // 2. Scan Strings for Hardcoded Secrets and Cleartext HTTP
  for (const str of ir.strings) {
    if (str.classification === 'key_or_token') {
      findings.push({
        id: `SEC-${counter++}`,
        category: 'hardcoded_secrets',
        severity: 'high',
        confidence: 'medium',
        title: 'Potential hardcoded API key or private secret',
        description: 'A high-entropy string matching token or secret patterns was embedded in the binary image.',
        affectedAddressOrFunction: 'Binary Static Data',
        supportingEvidence: [`Found string literal matching secret signature: ${str.value.substring(0, 24)}...`],
        remediation: 'Do not compile sensitive credentials into client-facing binaries. Use secure vaults or runtime environment variables.',
      });
    } else if (str.classification === 'url' && str.value.startsWith('http://') && !str.value.includes('localhost')) {
      findings.push({
        id: `SEC-${counter++}`,
        category: 'weak_cryptography',
        severity: 'medium',
        confidence: 'high',
        title: 'Cleartext HTTP communication endpoint',
        description: `The binary contains an unencrypted HTTP URL: ${str.value}`,
        affectedAddressOrFunction: 'Binary Static Data',
        supportingEvidence: [`Cleartext URL: ${str.value}`],
        remediation: 'Enforce HTTPS/TLS encryption for all external network endpoints to prevent interception.',
      });
    }
  }

  // 3. Scan IPC channels for wildcard channels
  for (const comp of ir.components) {
    if (comp.type === 'ipc_bridge' && (comp.name.includes('*') || comp.name.includes('eval'))) {
      findings.push({
        id: `SEC-${counter++}`,
        category: 'dangerous_ipc',
        severity: 'high',
        confidence: 'medium',
        title: `Permissive IPC bridge detected: '${comp.name}'`,
        description: `The IPC channel '${comp.name}' appears to accept dynamic or arbitrary code evaluation commands across contexts.`,
        affectedAddressOrFunction: comp.id,
        supportingEvidence: [`Component ID: ${comp.id}`, `Source file: ${comp.filePath || 'unspecified'}`],
        remediation: 'Scope IPC channels to strictly typed, explicit action handlers.',
      });
    }
  }

  return findings;
}
