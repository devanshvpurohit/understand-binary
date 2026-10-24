import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { safeExec } from '../utils/exec.js';
import type { DisassembledFunction, Instruction } from '../types.js';

export interface GhidraOptions {
  ghidraPath?: string;
  maxFunctions?: number;
  timeoutMs?: number;
}

export interface GhidraDecompileResult {
  success: boolean;
  engine: 'ghidra';
  functions: DisassembledFunction[];
  error?: string;
}

const CANDIDATE_GHIDRA_PATHS = [
  process.env.GHIDRA_HEADLESS,
  process.env.GHIDRA_HOME ? path.join(process.env.GHIDRA_HOME, 'support', 'analyzeHeadless') : undefined,
  '/opt/homebrew/Cellar/ghidra/12.1.4/libexec/support/analyzeHeadless',
  '/opt/homebrew/bin/analyzeHeadless',
  '/usr/local/bin/analyzeHeadless',
  '/Applications/ghidra/support/analyzeHeadless',
].filter(Boolean) as string[];

export function getGhidraHeadlessPath(): string | null {
  for (const candidate of CANDIDATE_GHIDRA_PATHS) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Check brew cellar dynamically
  try {
    const brewGhidraDir = '/opt/homebrew/Cellar/ghidra';
    if (fs.existsSync(brewGhidraDir)) {
      const versions = fs.readdirSync(brewGhidraDir);
      for (const ver of versions) {
        const headlessPath = path.join(brewGhidraDir, ver, 'libexec', 'support', 'analyzeHeadless');
        if (fs.existsSync(headlessPath)) {
          return headlessPath;
        }
      }
    }
  } catch {}

  return null;
}

export function isGhidraAvailable(): boolean {
  return getGhidraHeadlessPath() !== null;
}

const GHIDRA_JAVA_SCRIPT = `
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class GhidraExportJSON extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/ghidra_export.json";
        int maxFuncs = (args.length > 1) ? Integer.parseInt(args[1]) : 150;

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter(outPath));
        writer.println("[");

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        boolean first = true;

        while (iter.hasNext() && count < maxFuncs) {
            Function f = iter.next();
            if (f.isThunk() && count > 30) continue;

            DecompileResults res = decompiler.decompileFunction(f, 25, monitor);
            String cCode = (res != null && res.getDecompiledFunction() != null)
                ? res.getDecompiledFunction().getC()
                : "";

            if (!first) {
                writer.println(",");
            }
            first = false;

            writer.println("  {");
            writer.println("    \\"name\\": \\"" + escapeJson(f.getName()) + "\\",");
            writer.println("    \\"entrypoint\\": \\"" + f.getEntryPoint().toString() + "\\",");
            writer.println("    \\"isThunk\\": " + f.isThunk() + ",");
            writer.println("    \\"callers\\": " + getCallersJson(f) + ",");
            writer.println("    \\"callees\\": " + getCalleesJson(f) + ",");
            writer.println("    \\"pseudoCode\\": \\"" + escapeJson(cCode) + "\\"");
            writer.print("  }");

            count++;
        }

        writer.println();
        writer.println("]");
        writer.close();
        println("Ghidra exported " + count + " functions to " + outPath);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\\\", "\\\\\\\\")
                .replace("\\"", "\\\\\\"")
                .replace("\\b", "\\\\b")
                .replace("\\f", "\\\\f")
                .replace("\\n", "\\\\n")
                .replace("\\r", "\\\\r")
                .replace("\\t", "\\\\t");
    }

    private String getCallersJson(Function f) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        StringBuilder sb = new StringBuilder("[");
        int added = 0;
        while (refs.hasNext() && added < 10) {
            Reference r = refs.next();
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (caller != null && !caller.getName().equals(f.getName())) {
                if (added > 0) sb.append(", ");
                sb.append("\\"").append(escapeJson(caller.getName())).append("\\"");
                added++;
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String getCalleesJson(Function f) {
        Function[] called = f.getCalledFunctions(monitor).toArray(new Function[0]);
        StringBuilder sb = new StringBuilder("[");
        int limit = Math.min(called.length, 10);
        for (int i = 0; i < limit; i++) {
            if (i > 0) sb.append(", ");
            sb.append("\\"").append(escapeJson(called[i].getName())).append("\\"");
        }
        sb.append("]");
        return sb.toString();
    }
}
`;

export async function decompileWithGhidra(
  binaryPath: string,
  options: GhidraOptions = {}
): Promise<GhidraDecompileResult> {
  const ghidraBin = options.ghidraPath || getGhidraHeadlessPath();
  if (!ghidraBin || !fs.existsSync(ghidraBin)) {
    return {
      success: false,
      engine: 'ghidra',
      functions: [],
      error: 'Ghidra headless analyzer not found on system.',
    };
  }

  const tmpId = `ghidra_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const projDir = path.join(os.tmpdir(), `${tmpId}_proj`);
  const scriptDir = path.join(os.tmpdir(), `${tmpId}_scripts`);
  const outJson = path.join(os.tmpdir(), `${tmpId}_out.json`);
  const scriptPath = path.join(scriptDir, 'GhidraExportJSON.java');

  try {
    fs.mkdirSync(projDir, { recursive: true });
    fs.mkdirSync(scriptDir, { recursive: true });
    fs.writeFileSync(scriptPath, GHIDRA_JAVA_SCRIPT, 'utf-8');

    const maxFuncs = String(options.maxFunctions || 120);

    const args = [
      projDir,
      'ubTempProject',
      '-import',
      binaryPath,
      '-scriptPath',
      scriptDir,
      '-postScript',
      'GhidraExportJSON.java',
      outJson,
      maxFuncs,
      '-deleteProject',
      '-noanalysis',
    ];

    const result = await safeExec(ghidraBin, args, {
      timeoutMs: options.timeoutMs || 45000,
      maxBufferBytes: 20 * 1024 * 1024,
    });

    if (!fs.existsSync(outJson)) {
      return {
        success: false,
        engine: 'ghidra',
        functions: [],
        error: `Ghidra execution finished without generating output JSON. Stderr: ${result.stderr.slice(0, 300)}`,
      };
    }

    const rawJson = fs.readFileSync(outJson, 'utf-8');
    const parsed = JSON.parse(rawJson);

    const functions: DisassembledFunction[] = parsed.map((item: any) => {
      const name = item.name || 'sub_unknown';
      const address = item.entrypoint ? `0x${item.entrypoint.replace(/^0x/, '')}` : 'N/A';
      const isExported = !name.startsWith('FUN_') && !name.startsWith('thunk_FUN_');

      return {
        id: `fn_ghidra_${name.replace(/[^a-zA-Z0-9_]/g, '_')}`,
        name,
        address,
        isExported,
        isImported: item.isThunk || false,
        callers: Array.isArray(item.callers) ? item.callers : [],
        callees: Array.isArray(item.callees) ? item.callees : [],
        xrefs: [],
        instructions: [],
        pseudoCode: item.pseudoCode || `// Ghidra decompilation unavailable for ${name}`,
        detectedRole: inferRoleFromName(name),
        provenance: 'verified_fact' as const,
      };
    });

    return {
      success: true,
      engine: 'ghidra',
      functions,
    };
  } catch (err: any) {
    return {
      success: false,
      engine: 'ghidra',
      functions: [],
      error: err.message || String(err),
    };
  } finally {
    try {
      if (fs.existsSync(projDir)) fs.rmSync(projDir, { recursive: true, force: true });
      if (fs.existsSync(scriptDir)) fs.rmSync(scriptDir, { recursive: true, force: true });
      if (fs.existsSync(outJson)) fs.rmSync(outJson, { force: true });
    } catch {}
  }
}

function inferRoleFromName(name: string): string {
  const n = name.toLowerCase();
  if (n.includes('window') || n.includes('display') || n.includes('monitor') || n.includes('screen')) return 'ui';
  if (n.includes('proc') || n.includes('kill') || n.includes('pid')) return 'core';
  if (n.includes('http') || n.includes('socket') || n.includes('tls') || n.includes('net') || n.includes('curl')) return 'network';
  if (n.includes('crypto') || n.includes('sha') || n.includes('random') || n.includes('auth')) return 'security';
  if (n.includes('file') || n.includes('read') || n.includes('write')) return 'storage';
  if (n.includes('napi') || n.includes('register') || n.includes('ipc')) return 'ipc';
  return 'core';
}
