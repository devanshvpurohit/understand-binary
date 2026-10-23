import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';

export function startDashboardServer(graphDir: string, port = 3000): Promise<string> {
  const graphPath = path.join(graphDir, 'knowledge-graph.json');
  const irPath = path.join(graphDir, 'architecture-ir.json');

  if (!fs.existsSync(graphPath)) {
    throw new Error(`Knowledge graph not found at ${graphPath}. Run 'ub analyze <binary>' first.`);
  }

  const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || '/', `http://localhost:${port}`);

    if (url.pathname === '/api/graph') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      fs.createReadStream(graphPath).pipe(res);
      return;
    }

    if (url.pathname === '/api/ir') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (fs.existsSync(irPath)) {
        fs.createReadStream(irPath).pipe(res);
      } else {
        res.end(JSON.stringify({ error: 'No IR found' }));
      }
      return;
    }

    // Check if dashboard dist exists and serve static assets
    const dashboardDist = path.resolve(import.meta.dirname, '../../dashboard/dist');
    if (url.pathname.startsWith('/assets/') && fs.existsSync(dashboardDist)) {
      const assetPath = path.join(dashboardDist, url.pathname);
      if (fs.existsSync(assetPath)) {
        const ext = path.extname(assetPath);
        const contentType = ext === '.js' ? 'application/javascript' : ext === '.css' ? 'text/css' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        fs.createReadStream(assetPath).pipe(res);
        return;
      }
    }

    // Serve React production build index.html if present, else standalone dashboard
    if (fs.existsSync(path.join(dashboardDist, 'index.html'))) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(path.join(dashboardDist, 'index.html')).pipe(res);
      return;
    }

    // Fallback: Standalone Visual Dashboard
    const graphData = fs.readFileSync(graphPath, 'utf-8');
    const html = generateDashboardHTML(graphData);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      resolve(`http://localhost:${port}`);
    });
  });
}

function generateDashboardHTML(graphJson: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Understand-Binary Interactive Dashboard</title>
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
  <header class="h-16 border-b border-gray-800 bg-gray-900/80 backdrop-blur px-6 flex items-center justify-between shrink-0">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
        UB
      </div>
      <div>
        <h1 class="text-sm font-semibold tracking-wide flex items-center gap-2">
          <span id="target-title">Understand-Binary Explorer</span>
          <span id="target-format" class="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">Binary</span>
        </h1>
        <p class="text-xs text-gray-400" id="target-meta">Ingested Binary Technical Architecture</p>
      </div>
    </div>

    <!-- Center Search & Controls -->
    <div class="flex items-center gap-3">
      <input type="text" id="search-box" placeholder="Search functions, components, APIs..." class="px-3 py-1.5 bg-gray-800/80 border border-gray-700 rounded-lg text-sm focus:outline-none focus:border-cyan-500 w-64 text-gray-200">
      <button onclick="network.fit({ animation: true })" class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs font-medium rounded-lg border border-gray-700 transition">
        Reset View
      </button>
    </div>

    <!-- Metrics Badge -->
    <div class="flex items-center gap-4 text-xs">
      <div class="text-right">
        <div class="text-gray-400">Nodes / Edges</div>
        <div class="font-mono text-cyan-400" id="stats-counter">0 / 0</div>
      </div>
    </div>
  </header>

  <!-- Main Workspace -->
  <div class="flex flex-1 relative overflow-hidden">
    <!-- Network Graph Canvas -->
    <div id="network"></div>

    <!-- Right Drawer: Technical Inspector -->
    <aside id="inspector" class="w-96 border-l border-gray-800 bg-gray-900/90 backdrop-blur flex flex-col z-20 shrink-0 transform transition-transform duration-300 ease-in-out">
      <div class="p-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Symbol & Evidence Inspector</h2>
        <span id="node-type-badge" class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300">Selected</span>
      </div>

      <div class="p-5 flex-1 overflow-y-auto panel-scroll space-y-4">
        <div>
          <h3 id="inspect-name" class="text-base font-bold text-white break-all">Select a Node</h3>
          <p id="inspect-summary" class="text-xs text-gray-400 mt-1 leading-relaxed">Click any component, symbol, or API node on the graph to inspect decompiled code, memory addresses, and relationships.</p>
        </div>

        <div id="inspect-meta-section" class="hidden space-y-3">
          <div class="p-3 bg-gray-800/60 rounded-lg border border-gray-700/60 text-xs space-y-1.5 font-mono">
            <div class="flex justify-between"><span class="text-gray-400">Address:</span> <span id="meta-addr" class="text-cyan-400"></span></div>
            <div class="flex justify-between"><span class="text-gray-400">Role:</span> <span id="meta-role" class="text-amber-400"></span></div>
            <div class="flex justify-between"><span class="text-gray-400">Exported:</span> <span id="meta-export" class="text-emerald-400"></span></div>
          </div>

          <div>
            <label class="text-xs font-semibold text-gray-400 block mb-1.5">Decompiled / Pseudo-code</label>
            <pre id="inspect-code" class="p-3 bg-black/60 rounded-lg border border-gray-800 text-xs text-emerald-400 font-mono overflow-x-auto max-h-60 panel-scroll">// No code available</pre>
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold text-gray-400 block mb-1.5">Discovered Subsystem Layers</label>
          <div id="layers-list" class="space-y-1.5"></div>
        </div>
      </div>
    </aside>
  </div>

  <script>
    const graphData = ${graphJson};

    // Initialize Header Meta
    document.getElementById('target-title').innerText = graphData.project.name || 'Binary Application';
    document.getElementById('target-meta').innerText = graphData.project.description || 'Reconstructed Architecture';
    if (graphData.project.binaryTarget) {
      document.getElementById('target-format').innerText = graphData.project.binaryTarget.format.toUpperCase();
    }
    document.getElementById('stats-counter').innerText = graphData.nodes.length + ' / ' + graphData.edges.length;

    // Render Layers
    const layersList = document.getElementById('layers-list');
    graphData.layers.forEach(layer => {
      const el = document.createElement('div');
      el.className = 'p-2 rounded bg-gray-800/40 border border-gray-800 text-xs text-gray-300 flex justify-between items-center';
      el.innerHTML = '<span class="font-medium">' + layer.name + '</span><span class="text-gray-500 font-mono">' + layer.nodeIds.length + ' items</span>';
      layersList.appendChild(el);
    });

    // Color Palette
    const roleColors = {
      service: '#6366F1', // Indigo
      module: '#06B6D4',  // Cyan
      function: '#10B981',// Emerald
      endpoint: '#F59E0B',// Amber
      file: '#8B5CF6',    // Purple
    };

    // Build Vis-Network Nodes & Edges
    const visNodes = graphData.nodes.map(n => {
      const color = roleColors[n.type] || '#64748B';
      return {
        id: n.id,
        label: n.name,
        title: n.summary,
        color: {
          background: color,
          border: '#1E293B',
          highlight: { background: '#38BDF8', border: '#FFFFFF' }
        },
        shape: n.type === 'service' ? 'box' : n.type === 'endpoint' ? 'diamond' : 'dot',
        size: n.type === 'service' ? 24 : n.type === 'module' ? 18 : 12,
        font: { color: '#F1F5F9', size: 12, face: 'ui-sans-serif, system-ui' }
      };
    });

    const visEdges = graphData.edges.map(e => ({
      from: e.source,
      to: e.target,
      arrows: e.direction === 'forward' ? 'to' : undefined,
      color: { color: '#334155', highlight: '#38BDF8' },
      smooth: { type: 'continuous' },
      label: e.type === 'routes' ? 'ipc' : e.type === 'imports' ? 'imports' : undefined,
      font: { color: '#64748B', size: 9 }
    }));

    const container = document.getElementById('network');
    const data = {
      nodes: new vis.DataSet(visNodes),
      edges: new vis.DataSet(visEdges)
    };
    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -40,
          centralGravity: 0.01,
          springLength: 90,
          springConstant: 0.08
        },
        stabilization: { iterations: 150 }
      },
      interaction: {
        hover: true,
        tooltipDelay: 200
      }
    };

    const network = new vis.Network(container, data, options);

    // Inspector Click Handler
    network.on('click', function(params) {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = graphData.nodes.find(n => n.id === nodeId);
        if (node) {
          document.getElementById('inspect-name').innerText = node.name;
          document.getElementById('inspect-summary').innerText = node.summary;
          document.getElementById('node-type-badge').innerText = node.type.toUpperCase();

          const metaSection = document.getElementById('inspect-meta-section');
          if (node.binaryMeta) {
            metaSection.classList.remove('hidden');
            document.getElementById('meta-addr').innerText = node.binaryMeta.address || 'N/A';
            document.getElementById('meta-role').innerText = node.binaryMeta.role || 'general';
            document.getElementById('meta-export').innerText = node.binaryMeta.isExported ? 'YES' : 'NO';
            document.getElementById('inspect-code').innerText = node.binaryMeta.pseudoCode || '// No pseudo-code extracted';
          } else {
            metaSection.classList.add('hidden');
          }
        }
      }
    });

    // Search filter
    document.getElementById('search-box').addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) {
        network.fit();
        return;
      }
      const match = graphData.nodes.find(n => n.name.toLowerCase().includes(q) || (n.summary && n.summary.toLowerCase().includes(q)));
      if (match) {
        network.focus(match.id, { scale: 1.5, animation: true });
        network.selectNodes([match.id]);
      }
    });
  </script>
</body>
</html>`;
}
