import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ArchitectureIR } from '@understand-binary/bridge';
import {
  BinaryInspectionTools,
  BinaryInvestigator,
  scanSecurityFindings,
  generateSecurityAssessmentReport,
  GeminiProvider,
  ClaudeProvider,
  OpenAIProvider,
  OllamaProvider,
  type LLMProvider,
} from '@understand-binary/investigator';

export interface ClientProviderConfig {
  provider: string;
  apiKey?: string;
  model?: string;
  baseUrl?: string;
}

export interface ModelInfo {
  id: string;
  name: string;
  description?: string;
}

export function createCustomProvider(config?: ClientProviderConfig): LLMProvider | null {
  if (!config || !config.provider) return null;
  const p = config.provider.toLowerCase();
  if (p === 'gemini') {
    return new GeminiProvider(config.apiKey, config.model || 'gemini-1.5-flash');
  } else if (p === 'claude') {
    return new ClaudeProvider(config.apiKey, config.model || 'claude-3-5-sonnet-20241022');
  } else if (p === 'openai') {
    return new OpenAIProvider(config.apiKey, config.model || 'gpt-4o-mini');
  } else if (p === 'ollama') {
    return new OllamaProvider(config.baseUrl || 'http://localhost:11434', config.model || 'llama3.2');
  }
  return null;
}

export async function fetchProviderModels(config: ClientProviderConfig): Promise<ModelInfo[]> {
  const p = (config.provider || '').toLowerCase();
  if (p === 'gemini') {
    if (!config.apiKey) throw new Error('API key is required to list Gemini models');
    const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${config.apiKey}`);
    if (!resp.ok) {
      const errText = await resp.text();
      let msg = errText;
      try {
        const j = JSON.parse(errText);
        msg = j.error?.message || errText;
      } catch {}
      throw new Error(`Gemini API error: ${msg}`);
    }
    const data: any = await resp.json();
    const list: ModelInfo[] = (data.models || [])
      .filter((m: any) => m.supportedGenerationMethods?.includes('generateContent'))
      .map((m: any) => ({
        id: m.name.replace(/^models\//, ''),
        name: m.displayName || m.name.replace(/^models\//, ''),
        description: m.description,
      }));
    return list.sort((a, b) => {
      const aF = a.id.includes('flash');
      const bF = b.id.includes('flash');
      if (aF && !bF) return -1;
      if (!aF && bF) return 1;
      return a.id.localeCompare(b.id);
    });
  } else if (p === 'openai') {
    if (!config.apiKey) throw new Error('API key is required to list OpenAI models');
    const resp = await fetch('https://api.openai.com/v1/models', {
      headers: { Authorization: `Bearer ${config.apiKey}` },
    });
    if (!resp.ok) {
      const errText = await resp.text();
      let msg = errText;
      try {
        const j = JSON.parse(errText);
        msg = j.error?.message || errText;
      } catch {}
      throw new Error(`OpenAI API error: ${msg}`);
    }
    const data: any = await resp.json();
    const list: ModelInfo[] = (data.data || [])
      .filter((m: any) => m.id.startsWith('gpt-') || m.id.startsWith('o1') || m.id.startsWith('o3') || m.id.startsWith('chatgpt'))
      .map((m: any) => ({
        id: m.id,
        name: m.id,
      }));
    return list.sort((a, b) => a.id.localeCompare(b.id));
  } else if (p === 'claude') {
    try {
      const resp = await fetch('https://api.anthropic.com/v1/models', {
        headers: {
          'x-api-key': config.apiKey || '',
          'anthropic-version': '2023-06-01',
        },
      });
      if (resp.ok) {
        const data: any = await resp.json();
        if (data.data && Array.isArray(data.data)) {
          return data.data.map((m: any) => ({
            id: m.id,
            name: m.display_name || m.id,
          }));
        }
      }
    } catch {}
    return [
      { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet (Latest)' },
      { id: 'claude-3-5-haiku-20241022', name: 'Claude 3.5 Haiku' },
      { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus' },
    ];
  } else if (p === 'ollama') {
    const base = config.baseUrl || 'http://localhost:11434';
    const resp = await fetch(`${base}/api/tags`);
    if (!resp.ok) {
      throw new Error(`Ollama connection error (${resp.status}): ${await resp.text()}`);
    }
    const data: any = await resp.json();
    return (data.models || []).map((m: any) => ({
      id: m.name,
      name: m.name,
      description: m.size ? `${(m.size / (1024 * 1024 * 1024)).toFixed(1)} GB` : undefined,
    }));
  }
  return [];
}

export function startDashboardServer(graphDir: string, port = 3000): Promise<string> {
  const graphPath = path.join(graphDir, 'knowledge-graph.json');
  const irPath = path.join(graphDir, 'architecture-ir.json');
  const findingsPath = path.join(graphDir, 'security-findings.json');

  if (!fs.existsSync(graphPath)) {
    throw new Error(`Knowledge graph not found at ${graphPath}. Run 'ub analyze <binary>' first.`);
  }

  // Load IR into memory for interactive inspection & path queries
  let ir: ArchitectureIR | null = null;
  let tools: BinaryInspectionTools | null = null;
  let defaultInvestigator: BinaryInvestigator | null = null;

  if (fs.existsSync(irPath)) {
    try {
      ir = JSON.parse(fs.readFileSync(irPath, 'utf-8'));
      if (ir) {
        tools = new BinaryInspectionTools(ir);
        defaultInvestigator = new BinaryInvestigator(ir);
      }
    } catch {}
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${port}`);

    // GET /api/graph or /knowledge-graph.json
    if (url.pathname === '/api/graph' || url.pathname === '/knowledge-graph.json') {
      try {
        const raw = JSON.parse(fs.readFileSync(graphPath, 'utf-8'));
        if (!raw.project) raw.project = {};
        if (!raw.project.name) raw.project.name = path.basename(graphDir);
        if (!raw.project.languages || !Array.isArray(raw.project.languages)) {
          raw.project.languages = ['JavaScript', 'TypeScript', 'C++'];
        }
        if (!raw.project.frameworks || !Array.isArray(raw.project.frameworks)) {
          raw.project.frameworks = ['Electron', 'Node.js', 'Chromium'];
        }
        if (!raw.project.description) {
          raw.project.description = `Reconstructed Architecture Knowledge Graph for ${raw.project.name}`;
        }
        if (!raw.project.analyzedAt) {
          raw.project.analyzedAt = new Date().toISOString();
        }
        if (!raw.project.gitCommitHash) {
          raw.project.gitCommitHash = 'binary-reconstruction';
        }
        if (Array.isArray(raw.tour)) {
          for (const step of raw.tour) {
            if (!step.nodeIds || !Array.isArray(step.nodeIds)) {
              step.nodeIds = step.targetNodeIds || [];
            }
          }
        } else {
          raw.tour = [];
        }
        if (!Array.isArray(raw.layers)) {
          raw.layers = [];
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(raw));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        fs.createReadStream(graphPath).pipe(res);
      }
      return;
    }

    // GET /api/ir
    if (url.pathname === '/api/ir') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (fs.existsSync(irPath)) {
        fs.createReadStream(irPath).pipe(res);
      } else {
        res.end(JSON.stringify({ error: 'No IR found' }));
      }
      return;
    }

    // GET /api/findings
    if (url.pathname === '/api/findings') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (fs.existsSync(findingsPath)) {
        fs.createReadStream(findingsPath).pipe(res);
      } else if (ir) {
        const findings = scanSecurityFindings(ir);
        res.end(JSON.stringify(findings, null, 2));
      } else {
        res.end(JSON.stringify([]));
      }
      return;
    }

    // GET /api/report
    if (url.pathname === '/api/report') {
      const reportPath = path.join(graphDir, 'security-report.md');
      if (fs.existsSync(reportPath)) {
        res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8' });
        fs.createReadStream(reportPath).pipe(res);
        return;
      }
      if (ir) {
        const findings = fs.existsSync(findingsPath)
          ? JSON.parse(fs.readFileSync(findingsPath, 'utf-8'))
          : scanSecurityFindings(ir);
        const report = generateSecurityAssessmentReport(ir.targetInfo.filePath, ir, findings);
        res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8' });
        res.end(report);
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('# Security Assessment Report\n\nNo report available for this target.');
      return;
    }

    // GET /api/callpath?source=X&target=Y
    if (url.pathname === '/api/callpath') {
      const source = url.searchParams.get('source') || '';
      const target = url.searchParams.get('target') || '';
      if (!tools) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Analysis tools not loaded' }));
        return;
      }
      const pathResult = tools.findCallPath(source, target);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(pathResult, null, 2));
      return;
    }

    // POST /api/models (Fetch available models using user's API key)
    if (url.pathname === '/api/models' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const config = JSON.parse(body);
          const models = await fetchProviderModels(config);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, models }));
        } catch (err: any) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: err.message, models: [] }));
        }
      });
      return;
    }

    // POST /api/test-llm (In-browser LLM key test)
    if (url.pathname === '/api/test-llm' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const config = JSON.parse(body);
          const provider = createCustomProvider(config);
          if (!provider) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Unsupported or missing provider specification' }));
            return;
          }

          const pingResp = await provider.generateText([
            { role: 'user', content: 'Say "UB-LLM-OK" if you can read this message.' },
          ]);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              success: true,
              message: `Successfully connected to ${provider.name}`,
              snippet: pingResp.slice(0, 80).trim(),
            })
          );
        } catch (err: any) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: err.message || 'LLM connection failed' }));
        }
      });
      return;
    }

    // POST /api/investigate
    if (url.pathname === '/api/investigate' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const { question, providerConfig } = JSON.parse(body);
          let activeInvestigator = defaultInvestigator;

          // If browser client supplied custom LLM credentials, instantiate dynamically
          if (providerConfig && ir) {
            const customProvider = createCustomProvider(providerConfig);
            if (customProvider) {
              activeInvestigator = new BinaryInvestigator(ir, customProvider);
            }
          }

          if (!activeInvestigator) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Investigator not initialized' }));
            return;
          }

          const result = await activeInvestigator.investigate(question);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result, null, 2));
        } catch (err: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    // Serve static assets from packages/dashboard/dist (Understand-Anything bundle)
    const dashboardDist = path.resolve(import.meta.dirname, '../../dashboard/dist');
    if ((url.pathname.startsWith('/assets/') || url.pathname === '/favicon.ico' || url.pathname === '/favicon.svg') && fs.existsSync(dashboardDist)) {
      const assetPath = path.join(dashboardDist, url.pathname);
      if (fs.existsSync(assetPath)) {
        const ext = path.extname(assetPath);
        const contentType =
          ext === '.js' ? 'application/javascript' : ext === '.css' ? 'text/css' : ext === '.svg' ? 'image/svg+xml' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        fs.createReadStream(assetPath).pipe(res);
        return;
      }
    }

    // GET /meta.json, /config.json, /staleness.json, /diff-overlay.json (for Understand-Anything client)
    if (url.pathname === '/meta.json' || url.pathname === '/config.json' || url.pathname === '/staleness.json' || url.pathname === '/diff-overlay.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ outputLanguage: 'en', stale: false }));
      return;
    }

    if (url.pathname === '/domain-graph.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ version: '1.0.0', kind: 'domain', nodes: [], edges: [], layers: [] }));
      return;
    }

    // GET /ua - Direct Understand-Anything React Flow dashboard (zero key/token required)
    if (url.pathname === '/ua' || url.pathname === '/understand-anything') {
      const uaIndex = path.join(dashboardDist, 'index.html');
      if (fs.existsSync(uaIndex)) {
        let content = fs.readFileSync(uaIndex, 'utf-8');
        if (!content.includes('understand-anything-token')) {
          content = content.replace(
            '<head>',
            '<head><script>sessionStorage.setItem("understand-anything-token", "ub-open-access");</script>'
          );
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
        return;
      }
    }

    // Serve Standalone Visual Dashboard
    const graphData = fs.readFileSync(graphPath, 'utf-8');
    const irData = fs.existsSync(irPath) ? fs.readFileSync(irPath, 'utf-8') : '{}';
    const findingsData = fs.existsSync(findingsPath) ? fs.readFileSync(findingsPath, 'utf-8') : '[]';

    const html = generateEnhancedDashboardHTML(graphData, irData, findingsData);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      resolve(`http://localhost:${port}`);
    });
  });
}

function generateEnhancedDashboardHTML(graphJson: string, irJson: string, findingsJson: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>UB - Binary Architecture Intelligence</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <style>
    :root {
      --color-root: #0D0D0F;
      --color-surface: #141418;
      --color-raised: #1B1B22;
      --color-accent: #D4A373;
      --color-accent-bright: #F2BE8C;
      --color-accent-glow: #E8C49A;
      --color-text-primary: #F5F0EB;
      --color-text-secondary: #D4C4B7;
      --color-text-muted: #8E8276;
      --color-border-subtle: rgba(232, 196, 154, 0.12);
      --color-border-medium: rgba(232, 196, 154, 0.28);
      --color-cyan: #38BDF8;
      --color-crimson: #FF3366;
    }
    body {
      background-color: var(--color-root);
      color: var(--color-text-primary);
      font-family: "Inter", system-ui, -apple-system, sans-serif;
    }
    .font-display {
      font-family: "Space Grotesk", system-ui, sans-serif;
    }
    .font-mono-ua {
      font-family: "JetBrains Mono", monospace;
    }
    #network {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      background: radial-gradient(circle at center, #17171D 0%, #0D0D0F 100%);
    }
    .panel-scroll::-webkit-scrollbar { width: 5px; height: 5px; }
    .panel-scroll::-webkit-scrollbar-track { background: transparent; }
    .panel-scroll::-webkit-scrollbar-thumb { background: rgba(212, 163, 115, 0.22); border-radius: 4px; }
    .panel-scroll::-webkit-scrollbar-thumb:hover { background: rgba(212, 163, 115, 0.45); }
    /* Report Markdown styling */
    .report-prose h1 { font-family: "Space Grotesk", sans-serif; font-size: 1.6rem; font-weight: 600; color: #F2BE8C; margin-top: 1.5rem; margin-bottom: 0.75rem; border-bottom: 1px solid rgba(232, 196, 154, 0.15); padding-bottom: 0.5rem; }
    .report-prose h2 { font-family: "Space Grotesk", sans-serif; font-size: 1.3rem; font-weight: 600; color: #F5F0EB; margin-top: 2rem; margin-bottom: 0.5rem; border-bottom: 1px solid rgba(232, 196, 154, 0.15); padding-bottom: 0.4rem; }
    .report-prose h3 { font-size: 1.05rem; font-weight: 600; color: #E8C49A; margin-top: 1.25rem; margin-bottom: 0.4rem; }
    .report-prose h4 { font-size: 0.95rem; font-weight: 600; color: #D4C4B7; margin-top: 1rem; margin-bottom: 0.25rem; }
    .report-prose p { margin-bottom: 0.75rem; color: #D5CBBF; line-height: 1.6; font-size: 0.85rem; }
    .report-prose ul, .report-prose ol { margin-left: 1.5rem; margin-bottom: 0.75rem; font-size: 0.85rem; }
    .report-prose li { margin-bottom: 0.25rem; color: #D5CBBF; }
    .report-prose code { background: #1B1B22; color: #F2BE8C; padding: 0.15rem 0.35rem; border-radius: 0.25rem; font-family: "JetBrains Mono", monospace; font-size: 0.75rem; border: 1px solid rgba(232, 196, 154, 0.15); }
    .report-prose pre { background: #141418; border: 1px solid rgba(232, 196, 154, 0.15); border-radius: 0.5rem; padding: 1rem; overflow-x: auto; margin-bottom: 1rem; }
    .report-prose pre code { background: transparent; padding: 0; color: #7BD0FF; font-size: 0.75rem; border: none; }
    .report-prose table { width: 100%; border-collapse: collapse; margin-bottom: 1.25rem; font-size: 0.775rem; }
    .report-prose th { background: #1B1B22; color: #F2BE8C; text-align: left; padding: 0.5rem 0.75rem; border: 1px solid rgba(232, 196, 154, 0.2); }
    .report-prose td { padding: 0.5rem 0.75rem; border: 1px solid rgba(232, 196, 154, 0.1); color: #D5CBBF; }
    .report-prose tr:nth-child(even) { background: rgba(27, 27, 34, 0.6); }
    .report-prose blockquote { border-left: 3px solid #D4A373; padding-left: 1rem; color: #D4C4B7; margin-bottom: 0.75rem; }
  </style>
</head>
<body class="flex flex-col h-screen overflow-hidden bg-[#0D0D0F] text-[#F5F0EB]">
  <!-- Floating Focus Exit Pill (Hidden by default, shown in immersive focus mode) -->
  <div id="immersive-exit-btn" class="hidden fixed top-3 right-4 z-50">
    <button onclick="toggleImmersiveCanvas()" class="px-3.5 py-1.5 rounded bg-[#141418]/95 backdrop-blur border border-[#D4A373]/70 text-[#F2BE8C] hover:text-white text-xs font-semibold shadow-2xl flex items-center gap-2 transition hover:bg-[#1B1B22]">
      <span>✕ Exit Focus</span>
      <span class="text-[10px] text-[#A39787] font-mono-ua">(Esc)</span>
    </button>
  </div>

  <!-- Top Navigation Bar styled per Stitch "Obsidian Forge" Design System -->
  <header id="main-header" class="h-14 border-b border-[#E8C49A]/15 bg-[#141418]/90 backdrop-blur-md px-5 flex items-center justify-between shrink-0 z-30 transition-all duration-300">
    <div class="flex items-center gap-3">
      <!-- UB Brand Mark & Title -->
      <a href="/ua" class="flex items-center gap-2.5 group">
        <div class="w-8 h-8 rounded bg-gradient-to-tr from-[#D4A373] via-[#F2BE8C] to-[#E8C49A] flex items-center justify-center font-bold text-[#0D0D0F] shadow-md shadow-[#D4A373]/25 font-display text-sm border border-[#F2BE8C]/30">
          UB
        </div>
        <div class="flex items-baseline gap-2">
          <span class="font-display text-xl font-bold tracking-tight text-[#F5F0EB] group-hover:text-[#F2BE8C] transition">UB</span>
          <span class="text-[9.5px] font-mono-ua px-1.5 py-0.5 rounded border border-[#E8C49A]/30 bg-[#D4A373]/10 text-[#F2BE8C] font-semibold tracking-wider uppercase">Binary Intelligence</span>
        </div>
      </a>
      <span class="text-[#E8C49A]/20">|</span>
      <!-- Target Badge with Balatro active context -->
      <div class="flex items-center gap-1.5">
        <span id="target-title" class="text-xs font-mono-ua text-[#F5F0EB] font-semibold"></span>
        <span id="target-format" class="text-[10px] font-mono-ua px-2 py-0.5 rounded bg-[#1B1B22] text-[#F2BE8C] border border-[#E8C49A]/20 font-medium uppercase"></span>
        <span id="target-arch" class="text-[10px] font-mono-ua px-2 py-0.5 rounded bg-[#1B1B22] text-[#7BD0FF] border border-[#7BD0FF]/25 font-medium uppercase"></span>
        <span class="text-[10px] font-mono-ua px-2 py-0.5 rounded bg-[#1B1B22] text-[#06D6A0] border border-[#06D6A0]/25 font-medium hidden sm:inline-block">LÖVE2D RUNTIME</span>
      </div>
    </div>

    <!-- Center Navigation Tabs -->
    <div class="flex items-center gap-2">
      <div class="flex rounded-md bg-[#0D0D0F] p-1 text-xs font-medium border border-[#E8C49A]/15">
        <button id="tab-btn-flow" onclick="switchMainTab('flow')" class="px-3 py-1 rounded bg-[#D4A373] text-[#0D0D0F] font-bold transition flex items-center gap-1.5 shadow-sm">
          <span>⚡ Nodes Flow</span>
        </button>
        <button id="tab-btn-physics" onclick="switchMainTab('physics')" class="px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition flex items-center gap-1.5">
          <span>🪐 Force Network</span>
        </button>
        <button id="tab-btn-report" onclick="switchMainTab('report')" class="px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition flex items-center gap-1.5">
          <span>📋 Security Report</span>
        </button>
        <button id="tab-btn-path" onclick="switchMainTab('path')" class="px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition">
          Call Path
        </button>
        <button id="tab-btn-sec" onclick="switchMainTab('sec')" class="px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition flex items-center gap-1">
          Findings (<span id="sec-count" class="text-[#FF3366] font-bold">0</span>)
        </button>
        <button id="tab-btn-chat" onclick="switchMainTab('chat')" class="px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition">
          AI Chat
        </button>
      </div>
    </div>

    <!-- Right Controls -->
    <div class="flex items-center gap-2">
      <button onclick="toggleImmersiveCanvas()" class="px-2.5 py-1.5 rounded bg-[#1B1B22] hover:bg-[#25252F] border border-[#E8C49A]/20 text-[#F2BE8C] text-xs font-medium flex items-center gap-1.5 transition" title="Toggle 100% immersive canvas (hides header)">
        <span>⛶ Focus UB</span>
      </button>
      <a href="/ua" target="_blank" class="px-2.5 py-1.5 rounded bg-[#1B1B22] hover:bg-[#25252F] border border-[#E8C49A]/20 text-[#D4C4B7] hover:text-[#F5F0EB] text-xs font-medium flex items-center gap-1.5 transition" title="Open pure Understand-Binary graph in new tab">
        <span>UB Graph</span>
        <span class="text-[10px]">↗</span>
      </a>
      <button onclick="openLlmModal()" class="flex items-center gap-2 px-3 py-1.5 rounded bg-[#1B1B22] hover:bg-[#25252F] border border-[#E8C49A]/20 text-xs transition">
        <span id="llm-status-dot" class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span id="llm-status-text" class="text-[#D4C4B7] font-medium">LLM Config</span>
        <span class="text-[#D4C4B7] text-[11px]">⚙️</span>
      </button>
    </div>
  </header>

  <!-- High-Density Telemetry Status Strip -->
  <div class="h-7 border-b border-[#E8C49A]/10 bg-[#0E0E10] px-5 flex items-center justify-between text-[11px] font-mono-ua shrink-0">
    <div class="flex items-center gap-4">
      <span class="text-[#8E8276]">TARGET: <strong class="text-[#F2BE8C]" id="telemetry-target">Balatro.app</strong></span>
      <span class="text-white/10">|</span>
      <span class="text-[#8E8276]">NODES: <strong class="text-[#F5F0EB]" id="telemetry-nodes">845</strong></span>
      <span class="text-white/10">|</span>
      <span class="text-[#8E8276]">STATIC EDGES: <strong class="text-[#F5F0EB]" id="telemetry-edges">870</strong></span>
      <span class="text-white/10">|</span>
      <span class="text-[#8E8276]">FINDINGS: <strong class="text-[#FF3366]" id="telemetry-findings">11</strong></span>
    </div>
    <div class="flex items-center gap-3 text-[10px]">
      <span class="px-2 py-0.5 rounded bg-[#141418] border border-[#E8C49A]/15 text-[#D4C4B7]">GHIDRA 12.1 DECOMPILER</span>
      <span class="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-400">VERIFIED FACT IR</span>
    </div>
  </div>

  <!-- Main Workspace -->
  <div class="flex flex-1 relative overflow-hidden">
    <!-- View 1: Nodes Flow (Pure Understand-Binary Website View, Full Canvas) -->
    <div id="flow-view" class="flex-1 w-full h-full relative">
      <iframe src="/ua?token=ub-open-access" class="w-full h-full border-0 block" id="flow-iframe"></iframe>
    </div>

    <!-- View 2: Force-directed Physics Canvas -->
    <div id="physics-view" class="hidden flex-1 w-full h-full relative flex">
      <div class="flex-1 h-full relative overflow-hidden">
        <!-- Physics Filter Toolbar -->
        <div class="absolute top-4 left-4 z-20 flex flex-wrap items-center gap-2 bg-[#141418]/92 backdrop-blur-md p-1.5 rounded-lg border border-[#E8C49A]/20 shadow-2xl text-xs">
          <span class="text-[#8E8276] font-semibold px-1 font-mono-ua">FILTER:</span>
          <button id="filter-arch-btn" onclick="setGraphFilter('architecture')" class="px-2.5 py-1 rounded font-semibold bg-[#D4A373] text-[#0D0D0F] transition">
            🏛️ Architecture (<span id="count-arch">0</span>)
          </button>
          <button id="filter-services-btn" onclick="setGraphFilter('services')" class="px-2.5 py-1 rounded font-medium text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition">
            ⚡ Modules (<span id="count-services">0</span>)
          </button>
          <button id="filter-all-btn" onclick="setGraphFilter('all')" class="px-2.5 py-1 rounded font-medium text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition">
            🌐 All (<span id="count-all">0</span>)
          </button>
          <div class="h-4 w-px bg-white/10 mx-1"></div>
          <select id="layer-filter-select" onchange="filterByLayer(this.value)" class="bg-[#1B1B22] border border-[#E8C49A]/20 text-[#F5F0EB] text-xs rounded px-2 py-1 focus:outline-none">
            <option value="all">All Subsystems</option>
          </select>
          <div class="h-4 w-px bg-white/10 mx-1"></div>
          <button onclick="if(network) network.fit({ animation: { duration: 400 } })" class="px-2.5 py-1 bg-[#1B1B22] hover:bg-[#25252F] text-[#F2BE8C] rounded text-xs font-medium border border-[#E8C49A]/20" title="Fit All Nodes in View">
            ⛶ Fit View
          </button>
        </div>
        <div id="network" class="w-full h-full"></div>
      </div>
    </div>

    <!-- View 3: Security Assessment Report (17-section full document) -->
    <div id="report-view" class="hidden flex-1 flex flex-col bg-[#0D0D0F] overflow-hidden">
      <!-- Report Sub-header -->
      <div class="h-12 border-b border-[#E8C49A]/15 bg-[#141418]/90 px-6 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-3">
          <span class="text-xs font-semibold text-[#F5F0EB] flex items-center gap-2 font-display text-sm">
            <span>📋 Publication-Grade Assessment Report</span>
            <span class="text-[10px] px-2 py-0.5 rounded bg-[#D4A373]/15 text-[#F2BE8C] border border-[#E8C49A]/30 font-mono-ua">17 SECTIONS</span>
          </span>
          <span class="text-[#E8C49A]/20">|</span>
          <span class="text-xs text-[#8E8276]" id="report-meta">Decompiled via Ghidra 12.1 + AST Scanner</span>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="downloadReportMd()" class="px-3 py-1 rounded bg-[#1B1B22] hover:bg-[#25252F] text-xs border border-[#E8C49A]/20 text-[#F2BE8C] transition flex items-center gap-1.5 font-medium">
            <span>⬇ Download (.md)</span>
          </button>
          <button onclick="toggleReportRaw()" id="report-raw-btn" class="px-3 py-1 rounded bg-[#1B1B22] hover:bg-[#25252F] text-xs border border-[#E8C49A]/20 text-[#D4C4B7] hover:text-[#F5F0EB] transition">
            Raw Markdown
          </button>
        </div>
      </div>
      <!-- Report Body Container -->
      <div class="flex-1 overflow-y-auto panel-scroll p-8">
        <div class="max-w-4xl mx-auto">
          <div id="report-rendered" class="report-prose space-y-4">
            <div class="p-8 text-center text-[#8E8276] text-xs font-mono-ua">Loading Security Assessment Report...</div>
          </div>
          <pre id="report-raw" class="hidden p-6 bg-[#141418] rounded-lg border border-[#E8C49A]/15 font-mono-ua text-xs text-[#D5CBBF] overflow-x-auto whitespace-pre-wrap"></pre>
        </div>
      </div>
    </div>

    <!-- View 4: Call Path Explorer View -->
    <div id="path-view" class="hidden flex-1 p-8 overflow-y-auto bg-[#0D0D0F]">
      <div class="max-w-2xl mx-auto space-y-6">
        <div>
          <h2 class="text-xl font-bold font-display text-[#F2BE8C]">Execution-Flow Call Path Explorer</h2>
          <p class="text-xs text-[#8E8276] mt-1">Trace verified static call paths between any two functions or symbols in the binary.</p>
        </div>
        <div class="flex gap-3">
          <input type="text" id="path-source" placeholder="Source function or address (e.g. main_entry, love_init)" class="flex-1 px-3 py-2 bg-[#141418] border border-[#E8C49A]/20 rounded text-sm text-[#F5F0EB] focus:outline-none focus:border-[#D4A373] font-mono-ua">
          <input type="text" id="path-target" placeholder="Target function or address (e.g. _exit, SDL_Init)" class="flex-1 px-3 py-2 bg-[#141418] border border-[#E8C49A]/20 rounded text-sm text-[#F5F0EB] focus:outline-none focus:border-[#D4A373] font-mono-ua">
          <button onclick="runCallPathSearch()" class="px-4 py-2 bg-[#D4A373] hover:bg-[#F2BE8C] text-[#0D0D0F] rounded text-sm font-bold transition">Find Path</button>
        </div>
        <div id="path-result-box" class="p-4 bg-[#141418] border border-[#E8C49A]/15 rounded-lg font-mono-ua text-xs text-[#8E8276] min-h-32">
          Enter source and target functions above and click "Find Path".
        </div>
      </div>
    </div>

    <!-- View 5: Security Findings View -->
    <div id="sec-view" class="hidden flex-1 p-8 overflow-y-auto bg-[#0D0D0F]">
      <div class="max-w-3xl mx-auto space-y-4">
        <div>
          <h2 class="text-xl font-bold font-display text-[#F2BE8C]">Security-Oriented Static Findings</h2>
          <p class="text-xs text-[#8E8276] mt-1">Automated static analysis detecting dangerous APIs, weak crypto, and embedded cleartext endpoints.</p>
        </div>
        <div id="findings-container" class="space-y-3"></div>
      </div>
    </div>

    <!-- View 6: AI Investigation Chat View -->
    <div id="chat-view" class="hidden flex-1 flex flex-col bg-[#0D0D0F] p-6">
      <div class="flex-1 overflow-y-auto panel-scroll space-y-4 mb-4 max-w-3xl mx-auto w-full" id="chat-messages">
        <div class="p-4 rounded-lg bg-[#141418] border border-[#E8C49A]/15 text-xs text-[#D5CBBF]">
          <div class="flex items-center justify-between mb-1">
            <span class="font-display font-semibold text-base text-[#F2BE8C]">UB Binary Copilot</span>
            <span id="chat-provider-badge" class="font-mono-ua text-[10px] px-2 py-0.5 rounded bg-[#1B1B22] text-[#8E8276] border border-white/10">Offline Deterministic</span>
          </div>
          Ask any technical question about this binary (e.g. "Explain the Balatro startup flow", "Inspect card evaluation algorithms", "Where are unencrypted endpoints?"). Every response cites verified evidence.
        </div>
      </div>
      <div class="max-w-3xl mx-auto w-full flex gap-2">
        <input type="text" id="chat-input" onkeydown="if(event.key==='Enter') sendChatMessage()" placeholder="Ask a question about the binary architecture..." class="flex-1 px-4 py-2.5 bg-[#141418] border border-[#E8C49A]/20 rounded-lg text-sm text-[#F5F0EB] focus:outline-none focus:border-[#D4A373]">
        <button onclick="sendChatMessage()" class="px-5 py-2.5 bg-[#D4A373] hover:bg-[#F2BE8C] text-[#0D0D0F] rounded-lg text-sm font-bold transition">Ask</button>
      </div>
    </div>

    <!-- Right Drawer: Technical Inspector (Visible only in Physics Network mode) -->
    <aside id="inspector" class="hidden w-96 border-l border-[#E8C49A]/15 bg-[#141418]/95 backdrop-blur-md flex flex-col z-20 shrink-0">
      <div class="p-4 border-b border-[#E8C49A]/15 flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-[#F2BE8C] font-mono-ua">Symbol & Evidence Inspector</h2>
        <span id="node-provenance-badge" class="text-[10px] px-2 py-0.5 rounded bg-[#D4A373]/15 text-[#F2BE8C] border border-[#E8C49A]/30 font-mono-ua">VERIFIED FACT</span>
      </div>

      <div class="p-5 flex-1 overflow-y-auto panel-scroll space-y-4">
        <div>
          <h3 id="inspect-name" class="text-base font-bold text-[#F5F0EB] break-all font-mono-ua">Select a Node</h3>
          <p id="inspect-summary" class="text-xs text-[#8E8276] mt-1 leading-relaxed">Click any component, symbol, or API node on the graph to inspect disassembly instructions, memory addresses, and callers/callees.</p>
        </div>

        <div id="inspect-meta-section" class="hidden space-y-3">
          <div class="p-3 bg-[#1B1B22] rounded border border-[#E8C49A]/15 text-xs space-y-1.5 font-mono-ua">
            <div class="flex justify-between"><span class="text-[#8E8276]">Address:</span> <span id="meta-addr" class="text-[#7BD0FF]"></span></div>
            <div class="flex justify-between"><span class="text-[#8E8276]">Role:</span> <span id="meta-role" class="text-[#F2BE8C]"></span></div>
            <div class="flex justify-between"><span class="text-[#8E8276]">Callers:</span> <span id="meta-callers" class="text-[#F5F0EB]">0</span></div>
            <div class="flex justify-between"><span class="text-[#8E8276]">Callees:</span> <span id="meta-callees" class="text-[#F5F0EB]">0</span></div>
          </div>

          <div>
            <label class="text-xs font-semibold text-[#8E8276] block mb-1.5 font-mono-ua">Disassembled Instructions</label>
            <div id="inspect-instructions" class="p-3 bg-[#0D0D0F] rounded border border-[#E8C49A]/15 text-[11px] font-mono-ua text-emerald-400 overflow-x-auto max-h-60 panel-scroll space-y-1">
              // Select a function with instructions
            </div>
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold text-[#8E8276] block mb-1.5 font-mono-ua">Architectural Subsystems</label>
          <div id="layers-list" class="space-y-1.5"></div>
        </div>
      </div>
    </aside>
  </div>

  <!-- In-Browser LLM Configuration Modal -->
  <div id="llm-modal" class="fixed inset-0 z-50 bg-[#0D0D0F]/80 backdrop-blur-md hidden flex items-center justify-center p-4">
    <div class="bg-[#141418] border border-[#E8C49A]/20 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-[#E8C49A]/15">
        <div class="flex items-center gap-2">
          <span class="text-[#F2BE8C] text-lg">⚙️</span>
          <h3 class="font-bold text-[#F5F0EB] text-base font-display">In-Browser LLM Configuration</h3>
        </div>
        <button onclick="closeLlmModal()" class="text-[#8E8276] hover:text-white text-lg">&times;</button>
      </div>

      <p class="text-xs text-[#8E8276]">
        Configure an AI provider to investigate this binary using verified facts and disassembly evidence. Keys are stored safely in your browser (<code class="text-[#F2BE8C]">localStorage</code>) — no server <code class="text-[#F2BE8C]">.env</code> required.
      </p>

      <div class="space-y-3">
        <div>
          <label class="block text-xs font-semibold text-[#D4C4B7] mb-1">Provider</label>
          <select id="modal-llm-provider" onchange="onLlmProviderChange()" class="w-full bg-[#1B1B22] border border-[#E8C49A]/20 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#D4A373]">
            <option value="gemini">Google Gemini (Recommended - Fast & Accurate)</option>
            <option value="claude">Anthropic Claude (Sonnet 3.5)</option>
            <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
            <option value="ollama">Local Ollama (Offline / Private)</option>
          </select>
        </div>

        <div id="modal-apikey-group">
          <div class="flex justify-between items-center mb-1">
            <label class="text-xs font-semibold text-[#D4C4B7]">API Key</label>
            <span class="text-[10px] text-[#8E8276]" id="modal-apikey-hint">Stored in browser localStorage</span>
          </div>
          <div class="flex gap-2">
            <div class="relative flex-1">
              <input type="password" id="modal-llm-key" oninput="onApiKeyInput()" placeholder="Enter API Key (e.g. AIzaSy...)" class="w-full bg-[#1B1B22] border border-[#E8C49A]/20 rounded px-3 py-2 pr-10 text-xs text-white focus:outline-none focus:border-[#D4A373] font-mono-ua">
              <button type="button" onclick="toggleKeyVisibility()" class="absolute right-2.5 top-2 text-[#8E8276] hover:text-white text-xs">👁️</button>
            </div>
            <button type="button" onclick="loadModelsFromApi()" id="modal-fetch-models-btn" class="px-3 py-2 bg-[#1B1B22] hover:bg-[#25252F] text-[#F2BE8C] border border-[#E8C49A]/20 rounded text-xs font-medium transition flex items-center gap-1 shrink-0" title="Query provider API to get live list of models for this key">
              <span>🔄 Fetch Models</span>
            </button>
          </div>
        </div>

        <div>
          <div class="flex justify-between items-center mb-1">
            <label class="text-xs font-semibold text-[#D4C4B7]">Model Selection</label>
            <span class="text-[10px] text-[#7BD0FF]" id="modal-model-count-hint"></span>
          </div>
          <select id="modal-llm-model-select" onchange="onModelSelectChange()" class="w-full bg-[#1B1B22] border border-[#E8C49A]/20 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#D4A373] font-mono-ua">
            <option value="gemini-1.5-flash">gemini-1.5-flash (Default)</option>
            <option value="custom">Enter custom model name...</option>
          </select>
          <input type="text" id="modal-llm-model-custom" placeholder="Type custom model name..." class="hidden mt-2 w-full bg-[#1B1B22] border border-[#E8C49A]/20 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#D4A373] font-mono-ua">
        </div>

        <div id="modal-baseurl-group" class="hidden">
          <label class="block text-xs font-semibold text-[#D4C4B7] mb-1">Ollama Base URL</label>
          <input type="text" id="modal-llm-url" placeholder="http://localhost:11434" class="w-full bg-[#1B1B22] border border-[#E8C49A]/20 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#D4A373] font-mono-ua">
        </div>
      </div>

      <div id="modal-test-status" class="hidden p-2.5 rounded text-xs font-mono-ua"></div>

      <div class="pt-2 flex items-center justify-between border-t border-[#E8C49A]/15">
        <button onclick="clearLlmConfig()" class="text-xs text-[#FF3366] hover:underline">Clear & Use Offline</button>
        <div class="flex gap-2">
          <button onclick="testLlmConnection()" id="modal-test-btn" class="px-3 py-1.5 bg-[#1B1B22] hover:bg-[#25252F] text-[#D4C4B7] border border-[#E8C49A]/20 rounded text-xs font-medium transition">
            Test Connection
          </button>
          <button onclick="saveLlmConfig()" class="px-4 py-1.5 bg-[#D4A373] hover:bg-[#F2BE8C] text-[#0D0D0F] rounded text-xs font-bold transition">
            Save Settings
          </button>
        </div>
      </div>
    </div>
  </div>

  <script>
    const graphData = ${graphJson};
    const irData = ${irJson};
    const findingsData = ${findingsJson};

    // Header & Telemetry initialization
    const projectName = graphData.project.name || 'Balatro';
    document.getElementById('target-title').innerText = projectName;
    if (document.getElementById('telemetry-target')) {
      document.getElementById('telemetry-target').innerText = projectName + (graphData.project.binaryTarget ? ' (' + graphData.project.binaryTarget.format + ')' : '');
    }
    if (document.getElementById('telemetry-nodes')) {
      document.getElementById('telemetry-nodes').innerText = graphData.nodes.length;
    }
    if (document.getElementById('telemetry-edges')) {
      document.getElementById('telemetry-edges').innerText = graphData.edges.length;
    }
    if (document.getElementById('telemetry-findings')) {
      document.getElementById('telemetry-findings').innerText = findingsData.length;
    }
    if (graphData.project.binaryTarget) {
      document.getElementById('target-format').innerText = graphData.project.binaryTarget.format.toUpperCase();
      document.getElementById('target-arch').innerText = graphData.project.binaryTarget.arch.toUpperCase();
    }
    document.getElementById('sec-count').innerText = findingsData.length;

    // Populate Layers
    const layersList = document.getElementById('layers-list');
    const layerSelect = document.getElementById('layer-filter-select');
    graphData.layers.forEach(layer => {
      const el = document.createElement('div');
      el.className = 'p-2.5 rounded bg-[#1B1B22] border border-[#E8C49A]/15 text-xs text-[#D4C4B7] flex justify-between items-center cursor-pointer hover:border-[#D4A373]/40 transition';
      el.onclick = () => filterByLayer(layer.id);
      el.innerHTML = '<span class="font-medium text-[#F5F0EB]">' + layer.name + '</span><span class="text-[#8E8276] font-mono-ua text-[11px]">' + layer.nodeIds.length + ' items</span>';
      layersList.appendChild(el);

      const opt = document.createElement('option');
      opt.value = layer.id;
      opt.innerText = layer.name;
      layerSelect.appendChild(opt);
    });

    // Populate Counts
    const archNodes = graphData.nodes.filter(n => n.type === 'service' || n.type === 'module');
    const servicesNodes = graphData.nodes.filter(n => n.type === 'service' || n.type === 'module' || n.type === 'endpoint');
    document.getElementById('count-arch').innerText = archNodes.length;
    document.getElementById('count-services').innerText = servicesNodes.length;
    document.getElementById('count-all').innerText = graphData.nodes.length;

    // Render Findings View per Obsidian Forge Design System
    const findingsContainer = document.getElementById('findings-container');
    if (findingsData.length === 0) {
      findingsContainer.innerHTML = '<div class="p-4 bg-[#141418] border border-[#E8C49A]/15 rounded-lg text-xs text-[#8E8276]">No static security vulnerabilities or hardcoded secret patterns detected.</div>';
    } else {
      findingsData.forEach(f => {
        const borderCol = f.severity === 'critical' ? 'border-[#FF3366]/40 shadow-lg shadow-[#FF3366]/10' : f.severity === 'high' ? 'border-[#F2BE8C]/40' : 'border-[#7BD0FF]/30';
        const badgeCol = f.severity === 'critical' ? 'bg-[#FF3366]/15 text-[#FF3366] border-[#FF3366]/40' : f.severity === 'high' ? 'bg-[#D4A373]/15 text-[#F2BE8C] border-[#E8C49A]/30' : 'bg-[#7BD0FF]/15 text-[#7BD0FF] border-[#7BD0FF]/30';
        const card = document.createElement('div');
        card.className = 'p-4 rounded-lg bg-[#141418] border ' + borderCol + ' space-y-2';
        card.innerHTML = '<div class="flex items-center justify-between"><span class="text-[10px] px-2 py-0.5 rounded border font-mono-ua ' + badgeCol + '">' + f.severity.toUpperCase() + '</span><span class="text-xs font-mono-ua text-[#8E8276]">' + f.id + '</span></div>'
          + '<h3 class="text-sm font-bold text-[#F5F0EB] font-display">' + f.title + '</h3>'
          + '<p class="text-xs text-[#D5CBBF]">' + f.description + '</p>'
          + '<div class="text-[11px] font-mono-ua text-[#8E8276]">Location: <span class="text-[#7BD0FF]">' + f.affectedAddressOrFunction + '</span></div>'
          + '<div class="p-2.5 rounded bg-[#0D0D0F] border border-[#E8C49A]/15 text-[11px] text-emerald-400 font-mono-ua">Remediation: ' + f.remediation + '</div>';
        findingsContainer.appendChild(card);
      });
    }

    // Role Palette & Vis Nodes Construction
    const roleColors = {
      service: '#D4A373',    // Radiant Bronze (Subsystems)
      module: '#7BD0FF',     // Electric Cyan (Modules)
      endpoint: '#06D6A0',   // Emerald (APIs / Exports)
      function: '#9C8E82'    // Slate Bronze (Internal Functions)
    };

    // Pre-position nodes initially so physics runs smoothly without exploding
    const visNodesRaw = graphData.nodes.map((n, idx) => {
      const isBox = n.type === 'service' || n.type === 'module';
      const isEndpoint = n.type === 'endpoint';
      const angle = (idx / Math.max(1, graphData.nodes.length)) * 2 * Math.PI;
      const radius = n.type === 'service' ? 120 : (n.type === 'module' ? 300 : 550);
      const x = Math.round(Math.cos(angle) * radius + (Math.random() - 0.5) * 40);
      const y = Math.round(Math.sin(angle) * radius + (Math.random() - 0.5) * 40);
      return {
        id: n.id,
        label: n.name,
        x: x,
        y: y,
        title: n.name + '\\nType: ' + n.type + '\\nSummary: ' + (n.summary || ''),
        color: {
          background: roleColors[n.type] || '#475569',
          border: isBox ? '#F2BE8C' : '#50453B',
          highlight: { background: '#F2BE8C', border: '#FFFFFF' },
          hover: { background: '#E8C49A', border: '#FFFFFF' }
        },
        shape: isBox ? 'box' : (isEndpoint ? 'box' : 'dot'),
        margin: isBox ? 10 : 6,
        size: n.type === 'service' ? 26 : (n.type === 'module' ? 20 : 14),
        font: {
          color: '#FFFFFF',
          size: isBox ? 14 : (isEndpoint ? 12 : 11),
          face: 'ui-sans-serif, system-ui, sans-serif',
          strokeWidth: 2,
          strokeColor: '#0B0F17'
        },
        borderWidth: 2,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 6, x: 2, y: 2 },
        nodeType: n.type,
        layer: (n.tags && n.tags[0]) || 'general'
      };
    });

    const visEdgesRaw = graphData.edges.map(e => ({
      id: e.source + '->' + e.target,
      from: e.source,
      to: e.target,
      arrows: { to: { enabled: true, scaleFactor: 0.7 } },
      color: { color: '#334155', highlight: '#38BDF8', hover: '#60A5FA' },
      width: 1.5,
      smooth: { type: 'continuous' }
    }));

    const nodesDataSet = new vis.DataSet(visNodesRaw);
    const edgesDataSet = new vis.DataSet(visEdgesRaw);

    let currentFilter = 'architecture';
    let selectedLayer = 'all';

    const nodesView = new vis.DataView(nodesDataSet, {
      filter: function(item) {
        if (selectedLayer !== 'all') {
          const layerObj = graphData.layers.find(l => l.id === selectedLayer);
          if (layerObj && !layerObj.nodeIds.includes(item.id)) {
            return false;
          }
        }
        if (currentFilter === 'architecture') {
          return item.nodeType === 'service' || item.nodeType === 'module';
        }
        if (currentFilter === 'services') {
          return item.nodeType === 'service' || item.nodeType === 'module' || item.nodeType === 'endpoint';
        }
        return true;
      }
    });

    // Safely filter edges so no dangling edge exists in the view!
    const edgesView = new vis.DataView(edgesDataSet, {
      filter: function(edge) {
        const fromNode = nodesView.get(edge.from);
        const toNode = nodesView.get(edge.to);
        return !!(fromNode && toNode);
      }
    });

    const networkContainer = document.getElementById('network');
    const networkData = { nodes: nodesView, edges: edgesView };
    const networkOptions = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -70,
          centralGravity: 0.03,
          springLength: 100,
          springConstant: 0.06,
          damping: 0.35,
          avoidOverlap: 0.8
        },
        stabilization: {
          enabled: true,
          iterations: 60,
          updateInterval: 10
        }
      },
      interaction: {
        hover: true,
        navigationButtons: true,
        keyboard: true,
        zoomView: true
      }
    };

    let network = null;
    function initPhysicsNetwork() {
      if (!network && networkContainer) {
        network = new vis.Network(networkContainer, networkData, networkOptions);
        network.on('click', function(params) {
          if (params.nodes.length > 0) {
            selectNodeById(params.nodes[0]);
          }
        });
        setTimeout(() => { if (network) network.fit(); }, 200);
      }
    }

    // Graph Mode Switcher
    function setGraphMode(mode) {
      switchMainTab(mode === 'flow' ? 'flow' : 'physics');
    }

    // Filter Handlers
    function setGraphFilter(filter) {
      currentFilter = filter;
      ['arch', 'services', 'all'].forEach(f => {
        const btn = document.getElementById('filter-' + f + '-btn');
        if (btn) {
          if (f === filter) {
            btn.className = 'px-2.5 py-1 rounded-lg font-medium bg-[#D4A574] text-[#0A0A0A] transition';
          } else {
            btn.className = 'px-2.5 py-1 rounded-lg font-medium text-[#A39787] hover:text-[#F5F0EB] hover:bg-[#1A1A1A] transition';
          }
        }
      });
      nodesView.refresh();
      edgesView.refresh();
      if (network) {
        setTimeout(() => { network.fit({ animation: { duration: 300 } }); }, 100);
      }
    }

    function filterByLayer(layerId) {
      selectedLayer = layerId;
      document.getElementById('layer-filter-select').value = layerId;
      nodesView.refresh();
      edgesView.refresh();
      if (network) {
        setTimeout(() => { network.fit({ animation: { duration: 300 } }); }, 100);
      }
    }

    function searchGraph(query) {
      const q = query.trim().toLowerCase();
      if (!q) {
        if (network) network.fit({ animation: true });
        return;
      }
      const match = graphData.nodes.find(n => n.name.toLowerCase().includes(q) || n.id.toLowerCase().includes(q));
      if (match) {
        if (network) {
          network.focus(match.id, { scale: 1.4, animation: true });
        }
        selectNodeById(match.id);
      }
    }

    function selectNodeById(nodeId) {
      const node = graphData.nodes.find(n => n.id === nodeId);
      if (node) {
        document.getElementById('inspect-name').innerText = node.name;
        document.getElementById('inspect-summary').innerText = node.summary || 'No summary available.';
        const metaSec = document.getElementById('inspect-meta-section');
        if (node.binaryMeta) {
          metaSec.classList.remove('hidden');
          document.getElementById('meta-addr').innerText = node.binaryMeta.address || 'N/A';
          document.getElementById('meta-role').innerText = node.binaryMeta.role || 'general';

          const irSym = irData.symbols ? irData.symbols.find(s => s.id === node.id || s.address === node.binaryMeta.address) : null;
          if (irSym) {
            document.getElementById('meta-callers').innerText = (irSym.callers || []).length;
            document.getElementById('meta-callees').innerText = (irSym.callees || []).length;
            const instBox = document.getElementById('inspect-instructions');
            if (irSym.instructions && irSym.instructions.length > 0) {
              instBox.innerHTML = irSym.instructions.map(i => '<div class="flex gap-2 font-mono-ua"><span class="text-[#8E8276]">' + i.address + '</span><span class="text-[#7BD0FF] font-bold">' + i.mnemonic + '</span><span class="text-[#F5F0EB]">' + i.operands + (i.symbolStub ? ' <span class="text-[#F2BE8C]">(' + i.symbolStub + ')</span>' : '') + '</span></div>').join('');
            } else {
              instBox.innerText = node.binaryMeta.pseudoCode || '// No instruction disassembly recorded';
            }
          }
        } else {
          metaSec.classList.add('hidden');
        }
      }
    }

    let reportLoaded = false;
    let reportRawMode = false;
    window.reportMarkdown = '';

    async function loadSecurityReport() {
      if (reportLoaded && window.reportMarkdown) return;
      const renderedBox = document.getElementById('report-rendered');
      const rawBox = document.getElementById('report-raw');
      renderedBox.innerHTML = '<div class="p-8 text-center text-gray-500 text-xs">Loading publication-grade security report...</div>';
      try {
        const resp = await fetch('/api/report');
        if (!resp.ok) throw new Error('Failed to fetch security report (' + resp.status + ')');
        const md = await resp.text();
        window.reportMarkdown = md;
        reportLoaded = true;
        if (window.marked) {
          renderedBox.innerHTML = marked.parse(md);
        } else {
          renderedBox.innerText = md;
        }
        rawBox.innerText = md;
      } catch (err) {
        renderedBox.innerHTML = '<div class="p-8 text-center text-rose-400 text-xs">Failed to load report: ' + err.message + '</div>';
      }
    }

    function toggleReportRaw() {
      reportRawMode = !reportRawMode;
      const renderedBox = document.getElementById('report-rendered');
      const rawBox = document.getElementById('report-raw');
      const btn = document.getElementById('report-raw-btn');
      if (reportRawMode) {
        renderedBox.classList.add('hidden');
        rawBox.classList.remove('hidden');
        btn.innerText = 'Rendered View';
        btn.className = 'px-3 py-1 rounded-lg bg-[#D4A574] text-[#0A0A0A] font-semibold text-xs border border-[#D4A574] transition';
      } else {
        rawBox.classList.add('hidden');
        renderedBox.classList.remove('hidden');
        btn.innerText = 'Raw Markdown';
        btn.className = 'px-3 py-1 rounded-lg bg-[#161616] hover:bg-[#202020] text-xs border border-[#D4A574]/30 text-[#A39787] hover:text-[#F5F0EB] transition';
      }
    }

    function downloadReportMd() {
      if (!window.reportMarkdown) return;
      const blob = new Blob([window.reportMarkdown], { type: 'text/markdown;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'SECURITY_ASSESSMENT_REPORT.md';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }

    let isImmersive = false;
    function toggleImmersiveCanvas() {
      isImmersive = !isImmersive;
      const header = document.getElementById('main-header');
      const exitBtn = document.getElementById('immersive-exit-btn');
      if (isImmersive) {
        header.classList.add('hidden');
        exitBtn.classList.remove('hidden');
        switchMainTab('flow');
      } else {
        header.classList.remove('hidden');
        exitBtn.classList.add('hidden');
      }
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && isImmersive) {
        toggleImmersiveCanvas();
      }
    });

    function switchMainTab(tab) {
      const inspector = document.getElementById('inspector');
      ['flow', 'physics', 'report', 'path', 'sec', 'chat'].forEach(t => {
        const el = document.getElementById(t + '-view');
        const btn = document.getElementById('tab-btn-' + t);
        if (el) el.classList.add('hidden');
        if (btn) btn.className = 'px-3 py-1 rounded text-[#D4C4B7] hover:text-[#F5F0EB] hover:bg-[#1B1B22] transition flex items-center gap-1.5';
      });

      const activeEl = document.getElementById(tab + '-view');
      const activeBtn = document.getElementById('tab-btn-' + tab);
      if (activeEl) activeEl.classList.remove('hidden');
      if (activeBtn) activeBtn.className = 'px-3 py-1 rounded bg-[#D4A373] text-[#0D0D0F] font-bold transition flex items-center gap-1.5 shadow-sm';

      if (tab === 'physics') {
        if (inspector) inspector.classList.remove('hidden');
        initPhysicsNetwork();
        nodesView.refresh();
        edgesView.refresh();
        setTimeout(() => { if (network) network.fit({ animation: { duration: 300 } }); }, 100);
      } else {
        // Hide outer inspector on all other tabs so Nodes Flow (UA) and others have 100% full width!
        if (inspector) inspector.classList.add('hidden');
      }

      if (tab === 'report') {
        loadSecurityReport();
      }
    }

    async function runCallPathSearch() {
      const src = document.getElementById('path-source').value.trim();
      const tgt = document.getElementById('path-target').value.trim();
      const resBox = document.getElementById('path-result-box');
      if (!src || !tgt) return;
      resBox.innerText = 'Searching static call graph...';
      try {
        const res = await fetch('/api/callpath?source=' + encodeURIComponent(src) + '&target=' + encodeURIComponent(tgt));
        const data = await res.json();
        if (data.found) {
          resBox.innerHTML = '<div class="text-emerald-400 font-bold mb-2">✓ Verified Path Found (Length: ' + data.pathLength + ')</div>'
            + '<div class="space-y-1">' + data.path.map((p, idx) => '<div>' + (idx+1) + '. <span class="text-cyan-400">' + p.name + '</span> (' + p.address + ') [' + p.role + ']</div>').join('') + '</div>';
        } else {
          resBox.innerHTML = '<div class="text-amber-400">' + (data.message || data.error) + '</div>';
        }
      } catch (e) {
        resBox.innerText = 'Failed to execute call path search: ' + e.message;
      }
    }

    // ==========================================
    // In-Browser LLM Configuration & Chat Engine
    // ==========================================
    let apiKeyDebounceTimer = null;

    function getStoredLlmConfig() {
      try {
        return JSON.parse(localStorage.getItem('ub_llm_config') || 'null');
      } catch {
        return null;
      }
    }

    function updateLlmBadge() {
      const cfg = getStoredLlmConfig();
      const dot = document.getElementById('llm-status-dot');
      const text = document.getElementById('llm-status-text');
      const chatBadge = document.getElementById('chat-provider-badge');

      if (cfg && cfg.apiKey) {
        dot.className = 'w-2 h-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50';
        text.innerText = cfg.provider.toUpperCase() + ' (Active)';
        chatBadge.className = 'font-mono text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800';
        chatBadge.innerText = cfg.provider.toUpperCase() + ': ' + (cfg.model || 'default');
      } else if (cfg && cfg.provider === 'ollama') {
        dot.className = 'w-2 h-2 rounded-full bg-blue-400';
        text.innerText = 'Ollama (Local)';
        chatBadge.className = 'font-mono text-[10px] px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800';
        chatBadge.innerText = 'Ollama: ' + (cfg.model || 'llama3.2');
      } else {
        dot.className = 'w-2 h-2 rounded-full bg-gray-500';
        text.innerText = 'Offline LLM';
        chatBadge.className = 'font-mono text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700';
        chatBadge.innerText = 'Offline Deterministic';
      }
    }

    function openLlmModal() {
      const cfg = getStoredLlmConfig() || { provider: 'gemini', apiKey: '', model: 'gemini-1.5-flash', baseUrl: 'http://localhost:11434' };
      document.getElementById('modal-llm-provider').value = cfg.provider || 'gemini';
      document.getElementById('modal-llm-key').value = cfg.apiKey || '';
      document.getElementById('modal-llm-url').value = cfg.baseUrl || 'http://localhost:11434';
      document.getElementById('modal-test-status').classList.add('hidden');
      onLlmProviderChange(cfg.model);
      if (cfg.apiKey || cfg.provider === 'ollama') {
        loadModelsFromApi(cfg.model);
      }
      document.getElementById('llm-modal').classList.remove('hidden');
    }

    function closeLlmModal() {
      document.getElementById('llm-modal').classList.add('hidden');
    }

    function onApiKeyInput() {
      clearTimeout(apiKeyDebounceTimer);
      apiKeyDebounceTimer = setTimeout(() => {
        const key = document.getElementById('modal-llm-key').value.trim();
        if (key.length >= 10) {
          loadModelsFromApi();
        }
      }, 700);
    }

    async function loadModelsFromApi(selectedModelToKeep) {
      const prov = document.getElementById('modal-llm-provider').value;
      const key = document.getElementById('modal-llm-key').value.trim();
      const url = document.getElementById('modal-llm-url').value.trim();
      const hint = document.getElementById('modal-model-count-hint');
      const select = document.getElementById('modal-llm-model-select');
      const fetchBtn = document.getElementById('modal-fetch-models-btn');

      if (prov !== 'ollama' && !key) {
        hint.innerText = 'Enter key to list models';
        return;
      }

      hint.innerText = 'Fetching models...';
      fetchBtn.disabled = true;
      fetchBtn.classList.add('opacity-50');

      try {
        const res = await fetch('/api/models', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: prov, apiKey: key, baseUrl: url })
        });
        const data = await res.json();
        if (data.success && data.models && data.models.length > 0) {
          const currentVal = selectedModelToKeep || select.value;
          select.innerHTML = '';
          data.models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m.id;
            opt.innerText = m.name + (m.id !== m.name ? ' (' + m.id + ')' : '');
            select.appendChild(opt);
          });
          const customOpt = document.createElement('option');
          customOpt.value = 'custom';
          customOpt.innerText = 'Custom model name...';
          select.appendChild(customOpt);

          // Select matching model if found
          if (data.models.some(m => m.id === currentVal)) {
            select.value = currentVal;
          } else if (currentVal && currentVal !== 'custom') {
            const opt = document.createElement('option');
            opt.value = currentVal;
            opt.innerText = currentVal + ' (Custom)';
            select.insertBefore(opt, customOpt);
            select.value = currentVal;
          }
          hint.innerText = '✓ ' + data.models.length + ' models available for key';
          document.getElementById('modal-llm-model-custom').classList.add('hidden');
        } else {
          hint.innerText = data.error ? 'Fetch failed: ' + data.error.slice(0, 30) : 'Using defaults';
        }
      } catch (e) {
        hint.innerText = 'Fetch failed: ' + e.message;
      } finally {
        fetchBtn.disabled = false;
        fetchBtn.classList.remove('opacity-50');
      }
    }

    function onModelSelectChange() {
      const select = document.getElementById('modal-llm-model-select');
      const customInput = document.getElementById('modal-llm-model-custom');
      if (select.value === 'custom') {
        customInput.classList.remove('hidden');
        customInput.focus();
      } else {
        customInput.classList.add('hidden');
      }
    }

    function onLlmProviderChange(preferredModel) {
      const prov = document.getElementById('modal-llm-provider').value;
      const keyGroup = document.getElementById('modal-apikey-group');
      const urlGroup = document.getElementById('modal-baseurl-group');
      const select = document.getElementById('modal-llm-model-select');
      const customInput = document.getElementById('modal-llm-model-custom');

      customInput.classList.add('hidden');

      if (prov === 'ollama') {
        keyGroup.classList.add('hidden');
        urlGroup.classList.remove('hidden');
        select.innerHTML = '<option value="llama3.2">llama3.2</option><option value="codellama">codellama</option><option value="custom">Custom...</option>';
        if (preferredModel) select.value = preferredModel;
      } else {
        keyGroup.classList.remove('hidden');
        urlGroup.classList.add('hidden');
        if (prov === 'gemini') {
          select.innerHTML = '<option value="gemini-1.5-flash">gemini-1.5-flash (Fast & Recommended)</option><option value="gemini-1.5-pro">gemini-1.5-pro</option><option value="gemini-2.0-flash">gemini-2.0-flash</option><option value="custom">Custom...</option>';
        } else if (prov === 'claude') {
          select.innerHTML = '<option value="claude-3-5-sonnet-20241022">claude-3-5-sonnet-20241022</option><option value="claude-3-5-haiku-20241022">claude-3-5-haiku-20241022</option><option value="custom">Custom...</option>';
        } else if (prov === 'openai') {
          select.innerHTML = '<option value="gpt-4o-mini">gpt-4o-mini (Fast & Cost Effective)</option><option value="gpt-4o">gpt-4o</option><option value="o1-mini">o1-mini</option><option value="custom">Custom...</option>';
        }
        if (preferredModel && Array.from(select.options).some(o => o.value === preferredModel)) {
          select.value = preferredModel;
        }
      }
    }

    function toggleKeyVisibility() {
      const input = document.getElementById('modal-llm-key');
      input.type = input.type === 'password' ? 'text' : 'password';
    }

    function saveLlmConfig() {
      const prov = document.getElementById('modal-llm-provider').value;
      const key = document.getElementById('modal-llm-key').value.trim();
      const select = document.getElementById('modal-llm-model-select');
      const customInput = document.getElementById('modal-llm-model-custom');
      const model = select.value === 'custom' ? customInput.value.trim() : select.value;
      const url = document.getElementById('modal-llm-url').value.trim();

      const config = { provider: prov, apiKey: key, model: model, baseUrl: url };
      localStorage.setItem('ub_llm_config', JSON.stringify(config));
      updateLlmBadge();
      closeLlmModal();
    }

    function clearLlmConfig() {
      localStorage.removeItem('ub_llm_config');
      document.getElementById('modal-llm-key').value = '';
      updateLlmBadge();
      closeLlmModal();
    }

    async function testLlmConnection() {
      const prov = document.getElementById('modal-llm-provider').value;
      const key = document.getElementById('modal-llm-key').value.trim();
      const select = document.getElementById('modal-llm-model-select');
      const customInput = document.getElementById('modal-llm-model-custom');
      const model = select.value === 'custom' ? customInput.value.trim() : select.value;
      const url = document.getElementById('modal-llm-url').value.trim();
      const statusBox = document.getElementById('modal-test-status');

      statusBox.classList.remove('hidden');
      statusBox.className = 'p-2.5 rounded-lg text-xs font-mono bg-gray-800 text-cyan-400 animate-pulse';
      statusBox.innerText = 'Testing connection to ' + prov + ' (' + model + ')...';

      try {
        const res = await fetch('/api/test-llm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: prov, apiKey: key, model: model, baseUrl: url })
        });
        const data = await res.json();
        if (data.success) {
          statusBox.className = 'p-2.5 rounded-lg text-xs font-mono bg-emerald-950/80 border border-emerald-800 text-emerald-300';
          statusBox.innerText = '✓ Connection successful: ' + data.message + (data.snippet ? ' ("' + data.snippet + '")' : '');
        } else {
          statusBox.className = 'p-2.5 rounded-lg text-xs font-mono bg-red-950/80 border border-red-800 text-red-300';
          statusBox.innerText = '✗ Connection failed: ' + data.error;
        }
      } catch (e) {
        statusBox.className = 'p-2.5 rounded-lg text-xs font-mono bg-red-950/80 border border-red-800 text-red-300';
        statusBox.innerText = '✗ Network error: ' + e.message;
      }
    }

    async function sendChatMessage() {
      const input = document.getElementById('chat-input');
      const q = input.value.trim();
      if (!q) return;
      input.value = '';
      const box = document.getElementById('chat-messages');

      const userMsg = document.createElement('div');
      userMsg.className = 'p-3 rounded-xl bg-gray-800 text-xs text-white max-w-xl ml-auto';
      userMsg.innerText = q;
      box.appendChild(userMsg);

      const botMsg = document.createElement('div');
      botMsg.className = 'p-4 rounded-xl bg-gray-900 border border-gray-800 text-xs text-gray-300 max-w-2xl mr-auto space-y-2';
      botMsg.innerHTML = '<div class="text-cyan-400 animate-pulse font-medium">Investigating binary via tool calling...</div>';
      box.appendChild(botMsg);
      box.scrollTop = box.scrollHeight;

      const clientConfig = getStoredLlmConfig();

      try {
        const res = await fetch('/api/investigate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: q, providerConfig: clientConfig })
        });
        const data = await res.json();
        botMsg.innerHTML = '<div class="font-bold text-white mb-1">Answer</div><p class="leading-relaxed">' + data.summary + '</p>'
          + '<div class="pt-2 border-t border-gray-800"><div class="font-bold text-gray-400 mb-1">Verified Facts (' + data.provenFacts.length + ')</div><ul class="list-disc pl-4 space-y-1 text-gray-400">' + data.provenFacts.map(f => '<li>' + f + '</li>').join('') + '</ul></div>'
          + '<div class="pt-2 border-t border-gray-800"><div class="font-bold text-gray-400 mb-1">Evidence Citations</div><div class="space-y-1">' + data.evidenceCitations.map(c => '<div class="font-mono text-[11px] text-cyan-400">[' + c.addressOrSymbol + ']: ' + c.description + '</div>').join('') + '</div></div>';
      } catch (e) {
        botMsg.innerText = 'Investigation failed: ' + e.message;
      }
      box.scrollTop = box.scrollHeight;
    }

    // Initialize Badge on load
    updateLlmBadge();
    switchMainTab('flow');
  </script>
</body>
</html>`;
}
