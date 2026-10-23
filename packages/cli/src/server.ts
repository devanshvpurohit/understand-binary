import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ArchitectureIR } from '@understand-binary/bridge';
import { BinaryInspectionTools, BinaryInvestigator, scanSecurityFindings } from '@understand-binary/investigator';

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
  let investigator: BinaryInvestigator | null = null;

  if (fs.existsSync(irPath)) {
    try {
      ir = JSON.parse(fs.readFileSync(irPath, 'utf-8'));
      if (ir) {
        tools = new BinaryInspectionTools(ir);
        investigator = new BinaryInvestigator(ir);
      }
    } catch {}
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${port}`);

    // GET /api/graph
    if (url.pathname === '/api/graph') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      fs.createReadStream(graphPath).pipe(res);
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

    // POST /api/investigate
    if (url.pathname === '/api/investigate' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const { question } = JSON.parse(body);
          if (!investigator) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Investigator not initialized' }));
            return;
          }
          const result = await investigator.investigate(question);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result, null, 2));
        } catch (err: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    // Serve static assets from packages/dashboard/dist if present
    const dashboardDist = path.resolve(import.meta.dirname, '../../dashboard/dist');
    if (url.pathname.startsWith('/assets/') && fs.existsSync(dashboardDist)) {
      const assetPath = path.join(dashboardDist, url.pathname);
      if (fs.existsSync(assetPath)) {
        const ext = path.extname(assetPath);
        const contentType =
          ext === '.js' ? 'application/javascript' : ext === '.css' ? 'text/css' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        fs.createReadStream(assetPath).pipe(res);
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
    #network { width: 100%; height: calc(100vh - 65px); background: radial-gradient(circle at center, #131A29 0%, #0B0F17 100%); }
    .panel-scroll::-webkit-scrollbar { width: 6px; }
    .panel-scroll::-webkit-scrollbar-thumb { background: #2D3748; border-radius: 4px; }
  </style>
</head>
<body class="flex flex-col h-screen overflow-hidden">
  <!-- Top Navigation Bar -->
  <header class="h-16 border-b border-gray-800 bg-gray-900/90 backdrop-blur px-6 flex items-center justify-between shrink-0 z-30">
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

    <!-- Center Search & Controls -->
    <div class="flex items-center gap-3">
      <input type="text" id="search-box" placeholder="Search functions, addresses, strings..." class="px-3 py-1.5 bg-gray-800/80 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-cyan-500 w-64 text-gray-200">
      <button onclick="network.fit({ animation: true })" class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs font-medium rounded-lg border border-gray-700 transition">
        Reset View
      </button>
      <div class="h-6 w-px bg-gray-800"></div>
      <div class="flex rounded-lg bg-gray-800 p-0.5 text-xs font-medium border border-gray-700">
        <button id="tab-btn-graph" onclick="switchMainTab('graph')" class="px-3 py-1 rounded bg-cyan-600 text-white transition">Graph</button>
        <button id="tab-btn-path" onclick="switchMainTab('path')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">Call Path</button>
        <button id="tab-btn-sec" onclick="switchMainTab('sec')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">Findings (<span id="sec-count">0</span>)</button>
        <button id="tab-btn-chat" onclick="switchMainTab('chat')" class="px-3 py-1 rounded text-gray-400 hover:text-white transition">AI Chat</button>
      </div>
    </div>

    <!-- Metrics Badge -->
    <div class="flex items-center gap-4 text-xs font-mono">
      <div class="text-right">
        <div class="text-gray-400">Coverage</div>
        <div class="text-emerald-400 font-bold" id="coverage-status">COMPLETE</div>
      </div>
    </div>
  </header>

  <!-- Main Workspace -->
  <div class="flex flex-1 relative overflow-hidden">
    <!-- Network Graph View -->
    <div id="graph-view" class="flex-1 w-full h-full relative">
      <div id="network"></div>
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
          <div class="font-bold text-cyan-400 mb-1">Understand-Binary Investigator</div>
          Ask any technical question about this binary (e.g. "Explain the startup sequence", "Find code handling network requests", "Where is encryption or authentication implemented?"). Every response cites verified evidence.
        </div>
      </div>
      <div class="max-w-3xl mx-auto w-full flex gap-2">
        <input type="text" id="chat-input" onkeydown="if(event.key==='Enter') sendChatMessage()" placeholder="Ask a question about the binary..." class="flex-1 px-4 py-2.5 bg-gray-900 border border-gray-700 rounded-xl text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
        <button onclick="sendChatMessage()" class="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-sm font-medium transition">Ask</button>
      </div>
    </div>

    <!-- Right Drawer: Technical Inspector -->
    <aside id="inspector" class="w-96 border-l border-gray-800 bg-gray-900/90 backdrop-blur flex flex-col z-20 shrink-0">
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

    // Render Subsystem Layers
    const layersList = document.getElementById('layers-list');
    graphData.layers.forEach(layer => {
      const el = document.createElement('div');
      el.className = 'p-2 rounded bg-gray-800/40 border border-gray-800 text-xs text-gray-300 flex justify-between items-center';
      el.innerHTML = '<span class="font-medium">' + layer.name + '</span><span class="text-gray-500 font-mono">' + layer.nodeIds.length + ' items</span>';
      layersList.appendChild(el);
    });

    // Render Findings
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

    // Build Vis-Network Graph
    const roleColors = { service: '#6366F1', module: '#06B6D4', function: '#10B981', endpoint: '#F59E0B' };
    const visNodes = graphData.nodes.map(n => ({
      id: n.id,
      label: n.name,
      title: n.summary,
      color: { background: roleColors[n.type] || '#64748B', border: '#1E293B', highlight: { background: '#38BDF8', border: '#FFFFFF' } },
      shape: n.type === 'service' ? 'box' : n.type === 'endpoint' ? 'diamond' : 'dot',
      size: n.type === 'service' ? 24 : n.type === 'module' ? 18 : 12,
      font: { color: '#F1F5F9', size: 12 }
    }));
    const visEdges = graphData.edges.map(e => ({
      from: e.source,
      to: e.target,
      arrows: e.direction === 'forward' ? 'to' : undefined,
      color: { color: '#334155', highlight: '#38BDF8' },
      smooth: { type: 'continuous' }
    }));

    const network = new vis.Network(document.getElementById('network'), { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) }, {
      physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -40, centralGravity: 0.01, springLength: 90 }, stabilization: { iterations: 100 } }
    });

    network.on('click', function(params) {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = graphData.nodes.find(n => n.id === nodeId);
        if (node) {
          document.getElementById('inspect-name').innerText = node.name;
          document.getElementById('inspect-summary').innerText = node.summary;
          const metaSec = document.getElementById('inspect-meta-section');
          if (node.binaryMeta) {
            metaSec.classList.remove('hidden');
            document.getElementById('meta-addr').innerText = node.binaryMeta.address || 'N/A';
            document.getElementById('meta-role').innerText = node.binaryMeta.role || 'general';

            // Find matching IR symbol for full instruction stream
            const irSym = irData.symbols ? irData.symbols.find(s => s.id === node.id || s.address === node.binaryMeta.address) : null;
            if (irSym) {
              document.getElementById('meta-callers').innerText = irSym.callers.length;
              document.getElementById('meta-callees').innerText = irSym.callees.length;
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
    });

    function switchMainTab(tab) {
      ['graph', 'path', 'sec', 'chat'].forEach(t => {
        document.getElementById(t + '-view').classList.add('hidden');
        document.getElementById('tab-btn-' + t).className = 'px-3 py-1 rounded text-gray-400 hover:text-white transition';
      });
      document.getElementById(tab + '-view').classList.remove('hidden');
      document.getElementById('tab-btn-' + tab).className = 'px-3 py-1 rounded bg-cyan-600 text-white transition';
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

      try {
        const res = await fetch('/api/investigate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: q })
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
  </script>
</body>
</html>`;
}
