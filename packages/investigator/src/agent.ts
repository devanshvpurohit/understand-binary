import type { ArchitectureIR } from '@understand-binary/bridge';
import { BinaryInspectionTools } from './tools.js';
import { resolveLLMProvider, type LLMProvider } from './providers.js';
import { HybridRetriever } from './retrieval.js';
import { scanSecurityFindings } from './findings.js';

export interface InvestigationResult {
  question: string;
  summary: string;
  provenFacts: string[];
  hypotheses: string[];
  evidenceCitations: {
    addressOrSymbol: string;
    description: string;
    confidence: 'high' | 'medium' | 'low';
  }[];
  tracePath?: any;
  toolCallsExecuted: string[];
  followUpActions: string[];
}

export class BinaryInvestigator {
  private tools: BinaryInspectionTools;
  private retriever: HybridRetriever;
  private provider: LLMProvider | null;

  constructor(ir: ArchitectureIR, provider?: LLMProvider) {
    this.tools = new BinaryInspectionTools(ir);
    this.retriever = new HybridRetriever(ir, scanSecurityFindings(ir));
    this.provider = provider || resolveLLMProvider();
  }

  async investigate(question: string): Promise<InvestigationResult> {
    const qLower = question.toLowerCase();
    const toolCallsExecuted: string[] = [];
    const evidenceCitations: InvestigationResult['evidenceCitations'] = [];
    const provenFacts: string[] = [];
    const hypotheses: string[] = [];
    let tracePath: any = undefined;

    // 1. Tool Selection based on Question Intent
    if (qLower.includes('network') || qLower.includes('socket') || qLower.includes('http') || qLower.includes('api')) {
      toolCallsExecuted.push('list_functions(role: network)');
      toolCallsExecuted.push('search_strings(classification: url)');
      const funcs = this.tools.listFunctions(10, 0, 'network');
      const urls = this.tools.searchStrings(undefined, 'url');

      for (const f of funcs.functions) {
        provenFacts.push(`Network function '${f.name}' discovered at address ${f.address || 'N/A'}.`);
        evidenceCitations.push({
          addressOrSymbol: f.address || f.name,
          description: `Discovered function categorized under network operations with ${f.calleesCount} callees.`,
          confidence: 'high',
        });
      }
      for (const u of urls.strings.slice(0, 5)) {
        provenFacts.push(`Extracted URL literal: ${u.value}`);
      }
    }

    if (
      qLower.includes('crypt') ||
      qLower.includes('auth') ||
      qLower.includes('token') ||
      qLower.includes('key') ||
      qLower.includes('secret') ||
      qLower.includes('command')
    ) {
      toolCallsExecuted.push('list_functions(role: security)');
      toolCallsExecuted.push('search_strings(classification: key_or_token)');
      const secFuncs = this.tools.listFunctions(10, 0, 'security');
      const tokens = this.tools.searchStrings(undefined, 'key_or_token');

      for (const f of secFuncs.functions) {
        provenFacts.push(`Security/Crypto function '${f.name}' found at ${f.address || 'N/A'}.`);
        evidenceCitations.push({
          addressOrSymbol: f.address || f.name,
          description: `Cryptographic primitive or authentication handler verified in binary.`,
          confidence: 'high',
        });
      }
      for (const t of tokens.strings.slice(0, 3)) {
        provenFacts.push(`Hardcoded token/key pattern in binary data: ${t.value.substring(0, 20)}...`);
        evidenceCitations.push({
          addressOrSymbol: 'Binary Static Data',
          description: `String literal matching secret pattern: ${t.value.substring(0, 24)}...`,
          confidence: 'medium',
        });
      }
    }

    if (qLower.includes('startup') || qLower.includes('entry') || qLower.includes('init') || qLower.includes('main')) {
      toolCallsExecuted.push('get_function(main_entry)');
      toolCallsExecuted.push('get_callees(main_entry)');
      const mainFunc = this.tools.getFunction('main_entry');
      if (!('error' in mainFunc)) {
        provenFacts.push(`Primary execution entrypoint is '${mainFunc.function.name}' at address ${mainFunc.function.address}.`);
        provenFacts.push(`Startup routine directly dispatches to ${mainFunc.function.callees.length} verified callee targets: ${mainFunc.function.callees.join(', ')}.`);
        evidenceCitations.push({
          addressOrSymbol: mainFunc.function.address || mainFunc.function.name,
          description: `Entrypoint boundary instruction stream inspected.`,
          confidence: 'high',
        });
      }
    }

    // Call Path investigation (e.g. "path between X and Y" or "trace A to B")
    const pathMatch = /(?:path|trace|route)\s+(?:from|between)?\s*([a-zA-Z0-9_$.]+)\s+(?:to|and)\s+([a-zA-Z0-9_$.]+)/i.exec(question);
    if (pathMatch) {
      const [, src, tgt] = pathMatch;
      toolCallsExecuted.push(`find_call_path(${src}, ${tgt})`);
      tracePath = this.tools.findCallPath(src, tgt);
      if (tracePath.found) {
        provenFacts.push(`Verified static call path exists with length ${tracePath.pathLength}.`);
      } else {
        provenFacts.push(`No direct static call path was identified between '${src}' and '${tgt}'.`);
      }
    }

    // Default: Check Security Findings
    if (provenFacts.length === 0 || qLower.includes('security') || qLower.includes('vulnerab') || qLower.includes('safe')) {
      toolCallsExecuted.push('get_security_findings()');
      const sec = this.tools.getSecurityFindings();
      for (const finding of sec.findings.slice(0, 5)) {
        provenFacts.push(`[${finding.severity.toUpperCase()}] ${finding.title} in ${finding.affectedAddressOrFunction}`);
        evidenceCitations.push({
          addressOrSymbol: finding.affectedAddressOrFunction,
          description: finding.description,
          confidence: finding.confidence,
        });
      }
    }

    // Hybrid Semantic Retrieval (Phase 6 RAG)
    const retrieved = this.retriever.retrieve(question, 4);
    if (retrieved.length > 0) {
      toolCallsExecuted.push(`hybrid_retrieval(score_top: ${retrieved[0].score})`);
      for (const r of retrieved) {
        const fact = `[${r.kind.toUpperCase()}] ${r.title} at ${r.addressOrLocation}`;
        if (!provenFacts.includes(fact)) {
          provenFacts.push(fact);
        }
        if (!evidenceCitations.some((c) => c.addressOrSymbol === r.addressOrLocation)) {
          evidenceCitations.push({
            addressOrSymbol: r.addressOrLocation,
            description: `${r.title} (relevance score: ${r.score})`,
            confidence: 'high',
          });
        }
      }
    }

    // 2. Synthesize with LLM if provider is present
    let summary = '';
    if (this.provider) {
      try {
        const prompt = `You are a Principal Binary Reverse Engineer.
Answer the following user question about an analyzed binary application based ONLY on the verified factual evidence below.
Do not invent symbols, instructions, or vulnerabilities. Explicitly distinguish verified facts from hypotheses.

QUESTION: "${question}"

VERIFIED EVIDENCE:
${provenFacts.map((f) => `- ${f}`).join('\n')}

EVIDENCE CITATIONS:
${evidenceCitations.map((c) => `- [${c.addressOrSymbol}]: ${c.description}`).join('\n')}

Format your response with:
1. Direct Answer
2. Technical Explanation with cited addresses
3. Uncertainties or Unverified Hypotheses`;

        summary = await this.provider.generateText([
          { role: 'system', content: 'You are a senior reverse engineering expert.' },
          { role: 'user', content: prompt },
        ]);
      } catch (err: any) {
        summary = `LLM inference failed (${err.message}). Falling back to deterministic evidence synthesis.`;
      }
    }

    if (!summary) {
      summary = `Investigation completed via ${toolCallsExecuted.length} tool calls. Identified ${provenFacts.length} verified facts across analyzed functions and strings.`;
    }

    if (provenFacts.length === 0) {
      hypotheses.push('The requested functionality may be stripped, dynamically resolved at runtime, or encrypted.');
    }

    return {
      question,
      summary,
      provenFacts,
      hypotheses,
      evidenceCitations,
      tracePath,
      toolCallsExecuted,
      followUpActions: [
        'Inspect disassembly for cited function addresses',
        'Filter architecture graph by relevant subsystem',
        'Run call path explorer between entrypoint and destination function',
      ],
    };
  }
}
