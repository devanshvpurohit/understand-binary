import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ArchitectureIR } from '@understand-binary/bridge';
import {
  BinaryInspectionTools,
  BinaryInvestigator,
  scanSecurityFindings,
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
        if (!raw.project.languages || !Array.isArray(raw.project.languages)) {
          raw.project.languages = ['Lua', 'C++', 'Mach-O'];
        }
        if (!raw.project.frameworks || !Array.isArray(raw.project.frameworks)) {
          raw.project.frameworks = ['LÖVE2D', 'Cocoa', 'LuaJIT'];
        }
        if (Array.isArray(raw.tour)) {
          for (const step of raw.tour) {
            if (!step.nodeIds) step.nodeIds = step.targetNodeIds || [];
          }
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
  <title>Understand-Binary Interactive Platform</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body { background-color: #0B0F17; color: #E2E8F0; font-family: ui-sans-serif, system-ui, sans-serif; }
    #graph-view { position: relative; width: 100%; height: 100%; min-height: 500px; }
    #network { position: absolute; inset: 0; width: 100%; height: 100%; background: radial-gradient(circle at center, #131A29 0%, #0B0F17 100%); }
    .panel-scroll::-webkit-scrollbar { width: 6px; }
    .panel-scroll::-webkit-scrollbar-thumb { background: #2D3748; border-radius: 4px; }
  </style>
</head>
<body class="flex flex-col h-screen overflow-hidden">
  <!-- Top Navigation Bar -->
  <header class="h-16 border-b border-gray-800 bg-gray-900/95 backdrop-blur px-6 flex items-center justify-between shrink-0 z-30">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
        UB
      </div>
      <div>
        <h1 class="text-sm font-semibold tracking-wide flex items-center gap-2">
          <span id="target-title">Understand-Binary Explorer</span>
          <span id="target-format" class="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">BINARY</span>
          <span id="target-arch" class="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">ARM64</span>
        </h1>
        <p class="text-xs text-gray-400" id="target-meta">Verified Technical Architecture & Reconstructed Call Graph</p>
      </div>
    </div>

    <!-- Center Navigation Tabs -->
    <div class="flex items-center gap-3">
      <input type="text" id="search-box" oninput="searchGraph(this.value)" placeholder="Search symbols, functions..." class="px-3 py-1.5 bg-gray-800/80 border border-gray-700 rounded-lg text-xs focus:outline-none focus:border-cyan-500 w-52 text-gray-200">
      <div class="flex rounded-lg bg-gray-800 p-0.5 text-xs font-medium border border-gray-700">
        <button id="tab-btn-graph" onclick="switchMainTab('graph')" class="px-3 py-1 rounded bg-cyan-600 text-white transition">RE Graph</button>
        <button id="tab-btn-ua" onclick="switchMainTab('ua')" class="px-3 py-1 rounded text-indigo-400 hover:text-white transition flex items-center gap-1">✨ Understand-Anything</button>
        <button id="tab-btn-path" onclick="switchMainTab('path')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">Call Path</button>
        <button id="tab-btn-sec" onclick="switchMainTab('sec')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">Findings (<span id="sec-count">0</span>)</button>
        <button id="tab-btn-chat" onclick="switchMainTab('chat')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">AI Chat</button>
      </div>
    </div>

    <!-- Right Controls: Open UA in new tab + LLM Settings Trigger -->
    <div class="flex items-center gap-2.5">
      <a href="/ua" target="_blank" class="px-2.5 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/80 text-indigo-300 hover:text-white text-xs font-medium flex items-center gap-1.5 transition" title="Open Understand-Anything Flow in a full window">
        <span>Full UA View</span>
        <span class="text-[10px]">↗</span>
      </a>
      <button onclick="openLlmModal()" class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs transition">
        <span id="llm-status-dot" class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span id="llm-status-text" class="text-gray-300 font-medium">LLM Config</span>
        <span class="text-gray-400 text-[11px]">⚙️</span>
      </button>
    </div>
  </header>

  <!-- Main Workspace -->
  <div class="flex flex-1 relative overflow-hidden">
    <!-- Network Graph View -->
    <div id="graph-view" class="flex-1 w-full h-full relative">
      <!-- Floating View & Layer Filter Controls -->
      <div class="absolute top-4 left-4 z-10 flex flex-wrap items-center gap-2 bg-gray-900/90 backdrop-blur p-1.5 rounded-xl border border-gray-800 shadow-2xl text-xs">
        <span class="text-gray-400 font-semibold px-2">View:</span>
        <button id="filter-arch-btn" onclick="setGraphFilter('architecture')" class="px-3 py-1 rounded-lg font-medium text-gray-300 hover:text-white hover:bg-gray-800 transition">
          🏛️ Architecture (<span id="count-arch">0</span>)
        </button>
        <button id="filter-services-btn" onclick="setGraphFilter('services')" class="px-3 py-1 rounded-lg font-medium text-gray-300 hover:text-white hover:bg-gray-800 transition">
          ⚡ Modules & APIs (<span id="count-services">0</span>)
        </button>
        <button id="filter-all-btn" onclick="setGraphFilter('all')" class="px-3 py-1 rounded-lg font-medium bg-cyan-600 text-white transition">
          🌐 All Nodes (<span id="count-all">0</span>)
        </button>
        <div class="h-4 w-px bg-gray-800 mx-1"></div>
        <select id="layer-filter-select" onchange="filterByLayer(this.value)" class="bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded-lg px-2 py-1 focus:outline-none">
          <option value="all">All Subsystems</option>
        </select>
        <div class="h-4 w-px bg-gray-800 mx-1"></div>
        <button onclick="network.fit({ animation: { duration: 400 } })" class="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-cyan-400 rounded-lg text-xs font-medium border border-gray-700" title="Fit All Nodes in View">
          ⛶ Fit View
        </button>
      </div>

      <div id="network"></div>
    </div>

    <!-- Understand-Anything Embedded View (Zero token/key required) -->
    <div id="ua-view" class="hidden flex-1 w-full h-full relative bg-gray-950">
      <iframe src="/ua?token=ub-open-access" class="w-full h-full border-0" id="ua-iframe"></iframe>
    </div>

    <!-- Call Path Explorer View -->
    <div id="path-view" class="hidden flex-1 p-8 overflow-y-auto bg-gray-950">
      <div class="max-w-2xl mx-auto space-y-6">
        <div>
          <h2 class="text-lg font-bold text-white">Execution-Flow Call Path Explorer</h2>
          <p class="text-xs text-gray-400 mt-1">Trace verified static call paths between any two functions in the binary.</p>
        </div>
        <div class="flex gap-3">
          <input type="text" id="path-source" placeholder="Source function or address (e.g. main_entry)" class="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
          <input type="text" id="path-target" placeholder="Target function or address (e.g. _exit)" class="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
          <button onclick="runCallPathSearch()" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition">Find Path</button>
        </div>
        <div id="path-result-box" class="p-4 bg-gray-900 border border-gray-800 rounded-xl font-mono text-xs text-gray-300 min-h-32">
          Enter source and target functions above and click "Find Path".
        </div>
      </div>
    </div>

    <!-- Security Findings View -->
    <div id="sec-view" class="hidden flex-1 p-8 overflow-y-auto bg-gray-950">
      <div class="max-w-3xl mx-auto space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white">Security-Oriented Static Findings</h2>
          <p class="text-xs text-gray-400 mt-1">Automated static analysis detecting dangerous APIs, weak crypto, and embedded credentials.</p>
        </div>
        <div id="findings-container" class="space-y-3"></div>
      </div>
    </div>

    <!-- AI Investigation Chat View -->
    <div id="chat-view" class="hidden flex-1 flex flex-col bg-gray-950 p-6">
      <div class="flex-1 overflow-y-auto panel-scroll space-y-4 mb-4 max-w-3xl mx-auto w-full" id="chat-messages">
        <div class="p-4 rounded-xl bg-gray-900/80 border border-gray-800 text-xs text-gray-300">
          <div class="flex items-center justify-between mb-1">
            <span class="font-bold text-cyan-400">Understand-Binary Investigator</span>
            <span id="chat-provider-badge" class="font-mono text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700">Offline Deterministic</span>
          </div>
          Ask any technical question about this binary (e.g. "Explain the startup sequence", "Find code handling network requests", "Where is encryption or authentication implemented?"). Every response cites verified evidence.
        </div>
      </div>
      <div class="max-w-3xl mx-auto w-full flex gap-2">
        <input type="text" id="chat-input" onkeydown="if(event.key==='Enter') sendChatMessage()" placeholder="Ask a question about the binary..." class="flex-1 px-4 py-2.5 bg-gray-900 border border-gray-700 rounded-xl text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
        <button onclick="sendChatMessage()" class="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-sm font-medium transition">Ask</button>
      </div>
    </div>

    <!-- Right Drawer: Technical Inspector -->
    <aside id="inspector" class="w-96 border-l border-gray-800 bg-gray-900/95 backdrop-blur flex flex-col z-20 shrink-0">
      <div class="p-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Symbol & Evidence Inspector</h2>
        <span id="node-provenance-badge" class="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">VERIFIED FACT</span>
      </div>

      <div class="p-5 flex-1 overflow-y-auto panel-scroll space-y-4">
        <div>
          <h3 id="inspect-name" class="text-base font-bold text-white break-all">Select a Node</h3>
          <p id="inspect-summary" class="text-xs text-gray-400 mt-1 leading-relaxed">Click any component, symbol, or API node on the graph to inspect disassembly instructions, memory addresses, and callers/callees.</p>
        </div>

        <div id="inspect-meta-section" class="hidden space-y-3">
          <div class="p-3 bg-gray-800/60 rounded-lg border border-gray-700/60 text-xs space-y-1.5 font-mono">
            <div class="flex justify-between"><span class="text-gray-400">Address:</span> <span id="meta-addr" class="text-cyan-400"></span></div>
            <div class="flex justify-between"><span class="text-gray-400">Role:</span> <span id="meta-role" class="text-amber-400"></span></div>
            <div class="flex justify-between"><span class="text-gray-400">Callers:</span> <span id="meta-callers" class="text-white">0</span></div>
            <div class="flex justify-between"><span class="text-gray-400">Callees:</span> <span id="meta-callees" class="text-white">0</span></div>
          </div>

          <div>
            <label class="text-xs font-semibold text-gray-400 block mb-1.5">Disassembled Instructions</label>
            <div id="inspect-instructions" class="p-3 bg-black/60 rounded-lg border border-gray-800 text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-60 panel-scroll space-y-1">
              // Select a function with instructions
            </div>
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold text-gray-400 block mb-1.5">Architectural Subsystems</label>
          <div id="layers-list" class="space-y-1.5"></div>
        </div>
      </div>
    </aside>
  </div>

  <!-- In-Browser LLM Configuration Modal -->
  <div id="llm-modal" class="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm hidden flex items-center justify-center p-4">
    <div class="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <div class="flex items-center gap-2">
          <span class="text-cyan-400 text-lg">⚙️</span>
          <h3 class="font-bold text-white text-base">In-Browser LLM Configuration</h3>
        </div>
        <button onclick="closeLlmModal()" class="text-gray-400 hover:text-white text-lg">&times;</button>
      </div>

      <p class="text-xs text-gray-400">
        Configure an AI provider to investigate this binary using verified facts and disassembly evidence. Keys are stored safely in your browser (<code class="text-cyan-400">localStorage</code>) — no server <code class="text-cyan-400">.env</code> required.
      </p>

      <div class="space-y-3">
        <div>
          <label class="block text-xs font-semibold text-gray-300 mb-1">Provider</label>
          <select id="modal-llm-provider" onchange="onLlmProviderChange()" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500">
            <option value="gemini">Google Gemini (Recommended - Fast & Accurate)</option>
            <option value="claude">Anthropic Claude (Sonnet 3.5)</option>
            <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
            <option value="ollama">Local Ollama (Offline / Private)</option>
          </select>
        </div>

        <div id="modal-apikey-group">
          <div class="flex justify-between items-center mb-1">
            <label class="text-xs font-semibold text-gray-300">API Key</label>
            <span class="text-[10px] text-gray-500" id="modal-apikey-hint">Stored in browser localStorage</span>
          </div>
          <div class="flex gap-2">
            <div class="relative flex-1">
              <input type="password" id="modal-llm-key" oninput="onApiKeyInput()" placeholder="Enter API Key (e.g. AIzaSy...)" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 pr-10 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
              <button type="button" onclick="toggleKeyVisibility()" class="absolute right-2.5 top-2 text-gray-400 hover:text-white text-xs">👁️</button>
            </div>
            <button type="button" onclick="loadModelsFromApi()" id="modal-fetch-models-btn" class="px-3 py-2 bg-gray-800 hover:bg-gray-700 text-cyan-400 border border-gray-700 rounded-lg text-xs font-medium transition flex items-center gap-1 shrink-0" title="Query provider API to get live list of models for this key">
              <span>🔄 Fetch Models</span>
            </button>
          </div>
        </div>

        <div>
          <div class="flex justify-between items-center mb-1">
            <label class="text-xs font-semibold text-gray-300">Model Selection</label>
            <span class="text-[10px] text-cyan-400" id="modal-model-count-hint"></span>
          </div>
          <select id="modal-llm-model-select" onchange="onModelSelectChange()" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
            <option value="gemini-1.5-flash">gemini-1.5-flash (Default)</option>
            <option value="custom">Enter custom model name...</option>
          </select>
          <input type="text" id="modal-llm-model-custom" placeholder="Type custom model name..." class="hidden mt-2 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
        </div>

        <div id="modal-baseurl-group" class="hidden">
          <label class="block text-xs font-semibold text-gray-300 mb-1">Ollama Base URL</label>
          <input type="text" id="modal-llm-url" placeholder="http://localhost:11434" class="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
        </div>
      </div>

      <div id="modal-test-status" class="hidden p-2.5 rounded-lg text-xs font-mono"></div>

      <div class="pt-2 flex items-center justify-between border-t border-gray-800">
        <button onclick="clearLlmConfig()" class="text-xs text-red-400 hover:underline">Clear & Use Offline</button>
        <div class="flex gap-2">
          <button onclick="testLlmConnection()" id="modal-test-btn" class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 rounded-lg text-xs font-medium transition">
            Test Connection
          </button>
          <button onclick="saveLlmConfig()" class="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium transition">
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

    // Header initialization
    document.getElementById('target-title').innerText = graphData.project.name || 'Binary Application';
    document.getElementById('target-meta').innerText = graphData.project.description || 'Verified Technical Architecture';
    if (graphData.project.binaryTarget) {
      document.getElementById('target-format').innerText = graphData.project.binaryTarget.format.toUpperCase();
      document.getElementById('target-arch').innerText = graphData.project.binaryTarget.arch.toUpperCase();
    }
    document.getElementById('sec-count').innerText = findingsData.length;

    // Populate Layers & Layer Filter Select
    const layersList = document.getElementById('layers-list');
    const layerSelect = document.getElementById('layer-filter-select');
    graphData.layers.forEach(layer => {
      const el = document.createElement('div');
      el.className = 'p-2 rounded bg-gray-800/40 border border-gray-800 text-xs text-gray-300 flex justify-between items-center cursor-pointer hover:border-gray-700';
      el.onclick = () => filterByLayer(layer.id);
      el.innerHTML = '<span class="font-medium">' + layer.name + '</span><span class="text-gray-500 font-mono">' + layer.nodeIds.length + ' items</span>';
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

    // Render Findings View
    const findingsContainer = document.getElementById('findings-container');
    if (findingsData.length === 0) {
      findingsContainer.innerHTML = '<div class="p-4 bg-gray-900 border border-gray-800 rounded-xl text-xs text-gray-400">No static security vulnerabilities or hardcoded secret patterns detected.</div>';
    } else {
      findingsData.forEach(f => {
        const borderCol = f.severity === 'critical' ? 'border-red-500/40' : f.severity === 'high' ? 'border-amber-500/40' : 'border-blue-500/40';
        const badgeCol = f.severity === 'critical' ? 'bg-red-950 text-red-400 border-red-800' : f.severity === 'high' ? 'bg-amber-950 text-amber-400 border-amber-800' : 'bg-blue-950 text-blue-400 border-blue-800';
        const card = document.createElement('div');
        card.className = 'p-4 rounded-xl bg-gray-900 border ' + borderCol + ' space-y-2';
        card.innerHTML = '<div class="flex items-center justify-between"><span class="text-xs px-2 py-0.5 rounded border font-mono ' + badgeCol + '">' + f.severity.toUpperCase() + '</span><span class="text-xs font-mono text-gray-400">' + f.id + '</span></div>'
          + '<h3 class="text-sm font-bold text-white">' + f.title + '</h3>'
          + '<p class="text-xs text-gray-400">' + f.description + '</p>'
          + '<div class="text-[11px] font-mono text-gray-500">Location: ' + f.affectedAddressOrFunction + '</div>'
          + '<div class="p-2.5 rounded bg-black/40 border border-gray-800 text-[11px] text-emerald-400 font-mono">Remediation: ' + f.remediation + '</div>';
        findingsContainer.appendChild(card);
      });
    }

    // Role Palette & Vis Nodes Construction
    const roleColors = {
      service: '#4F46E5',    // Indigo (Subsystems)
      module: '#0284C7',     // Sky Blue (Modules)
      endpoint: '#D97706',   // Amber (APIs / Exports)
      function: '#059669'    // Emerald (Internal Functions)
    };

    const visNodesRaw = graphData.nodes.map(n => {
      const isBox = n.type === 'service' || n.type === 'module';
      const isEndpoint = n.type === 'endpoint';
      return {
        id: n.id,
        label: n.name,
        title: n.name + '\\nType: ' + n.type + '\\nSummary: ' + (n.summary || ''),
        color: {
          background: roleColors[n.type] || '#475569',
          border: isBox ? '#93C5FD' : '#334155',
          highlight: { background: '#38BDF8', border: '#FFFFFF' },
          hover: { background: '#60A5FA', border: '#FFFFFF' }
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

    let currentFilter = 'all';
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

    const networkContainer = document.getElementById('network');
    const networkData = { nodes: nodesView, edges: edgesDataSet };
    const networkOptions = {
      physics: {
        solver: 'barnesHut',
        barnesHut: {
          gravitationalConstant: -3500,
          centralGravity: 0.3,
          springLength: 120,
          springConstant: 0.04,
          damping: 0.09,
          avoidOverlap: 0.5
        },
        stabilization: {
          enabled: true,
          iterations: 120
        }
      },
      interaction: {
        hover: true,
        navigationButtons: true,
        keyboard: true,
        zoomView: true
      }
    };

    const network = new vis.Network(networkContainer, networkData, networkOptions);

    network.once('stabilizationIterationsDone', function() {
      network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    });

    setTimeout(() => { network.fit(); }, 200);
    setTimeout(() => { network.fit(); }, 800);
    window.addEventListener('resize', () => { network.fit(); });

    // Filter Handlers
    function setGraphFilter(filter) {
      currentFilter = filter;
      ['arch', 'services', 'all'].forEach(f => {
        const btn = document.getElementById('filter-' + f + '-btn');
        if (f === filter) {
          btn.className = 'px-3 py-1 rounded-lg font-medium bg-cyan-600 text-white transition';
        } else {
          btn.className = 'px-3 py-1 rounded-lg font-medium text-gray-300 hover:text-white hover:bg-gray-800 transition';
        }
      });
      nodesView.refresh();
      setTimeout(() => { network.fit({ animation: { duration: 300 } }); }, 150);
    }

    function filterByLayer(layerId) {
      selectedLayer = layerId;
      document.getElementById('layer-filter-select').value = layerId;
      nodesView.refresh();
      setTimeout(() => { network.fit({ animation: { duration: 300 } }); }, 150);
    }

    function searchGraph(query) {
      const q = query.trim().toLowerCase();
      if (!q) {
        network.fit({ animation: true });
        return;
      }
      const match = graphData.nodes.find(n => n.name.toLowerCase().includes(q) || n.id.toLowerCase().includes(q));
      if (match) {
        network.focus(match.id, { scale: 1.4, animation: true });
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
              instBox.innerHTML = irSym.instructions.map(i => '<div class="flex gap-2"><span class="text-gray-500">' + i.address + '</span><span class="text-cyan-400 font-bold">' + i.mnemonic + '</span><span class="text-gray-300">' + i.operands + (i.symbolStub ? ' (' + i.symbolStub + ')' : '') + '</span></div>').join('');
            } else {
              instBox.innerText = node.binaryMeta.pseudoCode || '// No instruction disassembly recorded';
            }
          }
        } else {
          metaSec.classList.add('hidden');
        }
      }
    }

    network.on('click', function(params) {
      if (params.nodes.length > 0) {
        selectNodeById(params.nodes[0]);
      }
    });

    function switchMainTab(tab) {
      ['graph', 'ua', 'path', 'sec', 'chat'].forEach(t => {
        const el = document.getElementById(t + '-view');
        const btn = document.getElementById('tab-btn-' + t);
        if (el) el.classList.add('hidden');
        if (btn) btn.className = 'px-3 py-1 rounded text-gray-400 hover:text-white transition';
      });
      const activeEl = document.getElementById(tab + '-view');
      const activeBtn = document.getElementById('tab-btn-' + tab);
      if (activeEl) activeEl.classList.remove('hidden');
      if (activeBtn) activeBtn.className = 'px-3 py-1 rounded bg-cyan-600 text-white transition';
      if (tab === 'graph') {
        setTimeout(() => { network.fit(); }, 100);
      }
      if (tab === 'ua') {
        const iframe = document.getElementById('ua-iframe');
        if (iframe && (!iframe.dataset.loaded || iframe.dataset.loaded === 'false')) {
          iframe.src = '/ua?token=ub-open-access&t=' + Date.now();
          iframe.dataset.loaded = 'true';
        }
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
  </script>
</body>
</html>`;
}
