import type { ArchitectureIR, SymbolIR } from '@understand-binary/bridge';
import type { SecurityFinding } from './findings.js';

export interface RetrievedChunk {
  id: string;
  kind: 'function' | 'string' | 'finding' | 'import';
  title: string;
  content: string;
  addressOrLocation: string;
  score: number;
  provenance: string;
}

export class HybridRetriever {
  private ir: ArchitectureIR;
  private findings: SecurityFinding[];

  constructor(ir: ArchitectureIR, findings: SecurityFinding[] = []) {
    this.ir = ir;
    this.findings = findings;
  }

  retrieve(query: string, limit = 8): RetrievedChunk[] {
    const q = query.toLowerCase().trim();
    const queryTokens = q.split(/\s+/).filter((t) => t.length > 2);
    const results: RetrievedChunk[] = [];

    // 1. Search Functions (Name, Address, Pseudocode, Role)
    for (const sym of this.ir.symbols) {
      let score = 0;
      const nameLower = sym.name.toLowerCase();
      const addrLower = (sym.address || '').toLowerCase();
      const codeLower = (sym.codeSnippet || '').toLowerCase();
      const roleLower = sym.role.toLowerCase();

      // Exact matches
      if (nameLower === q || addrLower === q) score += 100;
      else if (nameLower.includes(q) || addrLower.includes(q)) score += 50;

      // Token matches
      for (const token of queryTokens) {
        if (nameLower.includes(token)) score += 15;
        if (roleLower.includes(token)) score += 10;
        if (codeLower.includes(token)) score += 5;
      }

      if (score > 0) {
        results.push({
          id: sym.id,
          kind: 'function',
          title: `Function: ${sym.name} (${sym.role})`,
          content: sym.codeSnippet || `Routine at ${sym.address || 'N/A'} with ${sym.callees.length} callees`,
          addressOrLocation: sym.address || sym.name,
          score,
          provenance: sym.provenance,
        });
      }
    }

    // 2. Search Security Findings
    for (const f of this.findings) {
      let score = 0;
      const titleLower = f.title.toLowerCase();
      const descLower = f.description.toLowerCase();

      if (titleLower.includes(q)) score += 40;
      for (const token of queryTokens) {
        if (titleLower.includes(token) || descLower.includes(token)) score += 12;
      }

      if (score > 0) {
        results.push({
          id: f.id,
          kind: 'finding',
          title: `Security Finding [${f.severity.toUpperCase()}]: ${f.title}`,
          content: `${f.description}\nRemediation: ${f.remediation}`,
          addressOrLocation: f.affectedAddressOrFunction,
          score,
          provenance: 'verified_fact',
        });
      }
    }

    // 3. Search Strings
    for (const str of this.ir.strings) {
      const valLower = str.value.toLowerCase();
      if (valLower.includes(q)) {
        results.push({
          id: `str_${str.classification}`,
          kind: 'string',
          title: `Extracted String [${str.classification}]`,
          content: str.value,
          addressOrLocation: 'Binary Static Data',
          score: 25,
          provenance: 'verified_fact',
        });
      }
    }

    // Sort descending by score
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, limit);
  }

  getNeighborhood(symbolId: string, depth = 2): SymbolIR[] {
    const symbolMap = new Map<string, SymbolIR>();
    for (const s of this.ir.symbols) {
      symbolMap.set(s.id, s);
      if (s.address) symbolMap.set(s.address.toLowerCase(), s);
      symbolMap.set(s.name.toLowerCase(), s);
    }

    const visited = new Set<string>();
    const queue: { id: string; d: number }[] = [{ id: symbolId, d: 0 }];

    while (queue.length > 0) {
      const { id, d } = queue.shift()!;
      if (visited.has(id) || d > depth) continue;
      visited.add(id);

      const sym = symbolMap.get(id);
      if (sym) {
        for (const callee of sym.callees) {
          queue.push({ id: callee, d: d + 1 });
        }
        for (const caller of sym.callers) {
          queue.push({ id: caller, d: d + 1 });
        }
      }
    }

    const neighbors: SymbolIR[] = [];
    for (const id of visited) {
      const sym = symbolMap.get(id);
      if (sym && !neighbors.includes(sym)) neighbors.push(sym);
    }
    return neighbors;
  }
}
