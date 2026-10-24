import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface SafeExecOptions {
  timeoutMs?: number;
  maxBufferBytes?: number;
  env?: NodeJS.ProcessEnv;
}

export interface SafeExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
  error?: string;
}

/**
 * Safely execute an external binary synchronously using argument arrays to prevent command injection.
 */
export function safeExecSync(
  file: string,
  args: string[],
  options: SafeExecOptions = {}
): SafeExecResult {
  const timeout = options.timeoutMs ?? 15000;
  const maxBuffer = options.maxBufferBytes ?? 20 * 1024 * 1024;

  try {
    const stdout = execFileSync(file, args, {
      timeout,
      maxBuffer,
      env: { ...process.env, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    return {
      stdout: stdout.toString(),
      stderr: '',
      exitCode: 0,
      success: true,
    };
  } catch (err: any) {
    return {
      stdout: err.stdout ? err.stdout.toString() : '',
      stderr: err.stderr ? err.stderr.toString() : err.message,
      exitCode: err.status ?? 1,
      success: false,
      error: err.message,
    };
  }
}

/**
 * Safely execute an external binary using argument arrays to prevent command injection.
 * Enforces timeout and buffer limits.
 */
export async function safeExec(
  file: string,
  args: string[],
  options: SafeExecOptions = {}
): Promise<SafeExecResult> {
  const timeout = options.timeoutMs ?? 15000;
  const maxBuffer = options.maxBufferBytes ?? 20 * 1024 * 1024; // 20 MB

  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout,
      maxBuffer,
      env: { ...process.env, ...options.env },
    });

    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
      success: true,
    };
  } catch (err: any) {
    return {
      stdout: err.stdout ? err.stdout.toString() : '',
      stderr: err.stderr ? err.stderr.toString() : err.message,
      exitCode: err.code ?? 1,
      success: false,
      error: err.message,
    };
  }
}
