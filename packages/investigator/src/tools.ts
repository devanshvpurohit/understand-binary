import type { ArchitectureIR } from '@understand-binary/bridge';
import { scanSecurityFindings, type SecurityFinding } from './findings.js';

export interface AnalysisSession {
  ir: ArchitectureIR;
  findings: SecurityFinding[];
}

export class BinaryInspectionTools {
  private session: AnalysisSession;

  constructor(ir: ArchitectureIR) {
    this.session = {
      ir,
      findings: scanSecurityFindings(ir),
    };
  }

  getAnalysisStatus() {
    return {
      target: this.session.ir.targetInfo,
      coverage: this.session.ir.coverage,
      counts: {
        subsystems: this.session.ir.subsystems.length,
        components: this.session.ir.components.length,
        symbols: this.session.ir.symbols.length,
        relationships: this.session.ir.relationships.length,
        strings: this.session.ir.strings.length,
        findings: this.session.findings.length,
      },
    };
  }

  listFunctions(limit = 50, offset = 0, role?: string) {
    let funcs = this.session.ir.symbols;
    if (role) {
      funcs = funcs.filter((f) => f.role.toLowerCase() === role.toLowerCase());
    }
    const sliced = funcs.slice(offset, offset + limit);
    return {
      total: funcs.length,
      offset,
      limit,
      functions: sliced.map((f) => ({
        id: f.id,
        name: f.name,
        address: f.address,
        role: f.role,
        isExported: f.isExported,
        isImported: f.isImported,
        callersCount: f.callers.length,
        calleesCount: f.callees.length,
        provenance: f.provenance,
      })),
    };
  }

  getFunction(addressOrName: string) {
    const q = addressOrName.toLowerCase();
    const found = this.session.ir.symbols.find(
      (f) =>
        f.id.toLowerCase() === q ||
        (f.address && f.address.toLowerCase() === q) ||
        f.name.toLowerCase() === q
    );
    if (!found) {
      return { error: `Function '${addressOrName}' not found in analyzed binary.` };
    }
    return { function: found };
  }

  getDisassembly(addressOrName: string) {
    const res = this.getFunction(addressOrName);
    if ('error' in res) return res;
    const f = res.function;
    return {
      functionName: f.name,
      address: f.address,
      instructionsCount: f.instructions?.length || 0,
      instructions: f.instructions || [],
      pseudoCode: f.codeSnippet || null,
      provenance: f.provenance,
    };
  }

  getCallers(addressOrName: string) {
    const res = this.getFunction(addressOrName);
    if ('error' in res) return res;
    return {
      function: res.function.name,
      address: res.function.address,
      callers: res.function.callers,
      xrefs: res.function.callers.map((c) => ({ caller: c, verified: true })),
    };
  }

  getCallees(addressOrName: string) {
    const res = this.getFunction(addressOrName);
    if ('error' in res) return res;
    return {
      function: res.function.name,
      address: res.function.address,
      callees: res.function.callees,
    };
  }

  searchStrings(pattern?: string, classification?: string) {
    let strs = this.session.ir.strings;
    if (classification) {
      strs = strs.filter((s) => s.classification === classification);
    }
    if (pattern) {
      const p = pattern.toLowerCase();
      strs = strs.filter((s) => s.value.toLowerCase().includes(p));
    }
    return {
      totalMatches: strs.length,
      strings: strs.slice(0, 100),
    };
  }

  searchSymbols(pattern: string) {
    const p = pattern.toLowerCase();
    const matches = this.session.ir.symbols.filter(
      (s) => s.name.toLowerCase().includes(p) || (s.address && s.address.toLowerCase().includes(p))
    );
    return {
      totalMatches: matches.length,
      symbols: matches.slice(0, 50).map((m) => ({
        id: m.id,
        name: m.name,
        address: m.address,
        role: m.role,
        isExported: m.isExported,
      })),
    };
  }

  findCallPath(sourceQuery: string, targetQuery: string) {
    const srcRes = this.getFunction(sourceQuery);
    const tgtRes = this.getFunction(targetQuery);

    if ('error' in srcRes) return srcRes;
    if ('error' in tgtRes) return tgtRes;

    const sourceId = srcRes.function.id;
    const targetId = tgtRes.function.id;

    // BFS shortest path search on call graph
    const queue: string[][] = [[sourceId]];
    const visited = new Set<string>([sourceId]);

    const symbolMap = new Map<string, typeof srcRes.function>();
    for (const s of this.session.ir.symbols) {
      symbolMap.set(s.id, s);
      if (s.address) symbolMap.set(s.address.toLowerCase(), s);
      symbolMap.set(s.name.toLowerCase(), s);
    }

    while (queue.length > 0) {
      const path = queue.shift()!;
      const current = path[path.length - 1];

      if (current === targetId) {
        return {
          found: true,
          pathLength: path.length,
          path: path.map((id) => {
            const sym = symbolMap.get(id);
            return {
              id,
              name: sym?.name || id,
              address: sym?.address || 'N/A',
              role: sym?.role || 'general',
            };
          }),
        };
      }

      const sym = symbolMap.get(current);
      if (sym) {
        for (const callee of sym.callees) {
          const calleeSym = symbolMap.get(callee) || symbolMap.get(callee.toLowerCase());
          const nextId = calleeSym ? calleeSym.id : callee;

          if (!visited.has(nextId)) {
            visited.add(nextId);
            queue.push([...path, nextId]);
          }
        }
      }
    }

    return {
      found: false,
      message: `No static call path discovered between '${srcRes.function.name}' and '${tgtRes.function.name}'.`,
    };
  }

  getSecurityFindings() {
    return {
      total: this.session.findings.length,
      findings: this.session.findings,
    };
  }
}
