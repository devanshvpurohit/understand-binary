import { useEffect, useRef, useState } from 'react';
import type { KnowledgeGraph, GraphNode } from '@understand-binary/graph-engine';

declare const vis: any;

export default function App() {
  const [graph, setGraph] = useState<KnowledgeGraph | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedLayer, setSelectedLayer] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<any>(null);

  useEffect(() => {
    fetch('/api/graph')
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load knowledge graph from server');
        return res.json();
      })
      .then((data: KnowledgeGraph) => {
        setGraph(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!graph || !containerRef.current || typeof vis === 'undefined') return;

    // Filter nodes by layer if selected
    const filteredNodes = graph.nodes.filter((n) => {
      if (selectedLayer !== 'all') {
        const layer = graph.layers.find((l) => l.id === selectedLayer);
        if (layer && !layer.nodeIds.includes(n.id)) return false;
      }
      return true;
    });

    const activeNodeIds = new Set(filteredNodes.map((n) => n.id));

    const roleColors: Record<string, string> = {
      service: '#6366F1',
      module: '#06B6D4',
      function: '#10B981',
      endpoint: '#F59E0B',
      file: '#8B5CF6',
    };

    const visNodes = filteredNodes.map((n) => {
      const color = roleColors[n.type] || '#64748B';
      return {
        id: n.id,
        label: n.name,
        title: n.summary,
        color: {
          background: color,
          border: '#1E293B',
          highlight: { background: '#38BDF8', border: '#FFFFFF' },
        },
        shape: n.type === 'service' ? 'box' : n.type === 'endpoint' ? 'diamond' : 'dot',
        size: n.type === 'service' ? 24 : n.type === 'module' ? 18 : 12,
        font: { color: '#F1F5F9', size: 12 },
      };
    });

    const visEdges = graph.edges
      .filter((e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target))
      .map((e) => ({
        from: e.source,
        to: e.target,
        arrows: e.direction === 'forward' ? 'to' : undefined,
        color: { color: '#334155', highlight: '#38BDF8' },
        smooth: { type: 'continuous' },
        label: e.type === 'routes' ? 'ipc' : e.type === 'imports' ? 'imports' : undefined,
        font: { color: '#64748B', size: 9 },
      }));

    const data = {
      nodes: new vis.DataSet(visNodes),
      edges: new vis.DataSet(visEdges),
    };

    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -40,
          centralGravity: 0.01,
          springLength: 90,
          springConstant: 0.08,
        },
        stabilization: { iterations: 150 },
      },
      interaction: {
        hover: true,
      },
    };

    const net = new vis.Network(containerRef.current, data, options);
    networkRef.current = net;

    net.on('click', (params: any) => {
      if (params.nodes && params.nodes.length > 0) {
        const id = params.nodes[0];
        const found = graph.nodes.find((n) => n.id === id);
        setSelectedNode(found || null);
      }
    });

    return () => {
      net.destroy();
    };
  }, [graph, selectedLayer]);

  const handleSearch = (q: string) => {
    setSearchQuery(q);
    if (!networkRef.current || !graph) return;
    if (!q.trim()) {
      networkRef.current.fit({ animation: true });
      return;
    }
    const match = graph.nodes.find(
      (n) => n.name.toLowerCase().includes(q.toLowerCase()) || n.summary.toLowerCase().includes(q.toLowerCase())
    );
    if (match) {
      networkRef.current.focus(match.id, { scale: 1.5, animation: true });
      networkRef.current.selectNodes([match.id]);
      setSelectedNode(match);
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#0B0F17] text-slate-100">
      {/* Top Header */}
      <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
            UB
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-wide flex items-center gap-2">
              <span>{graph?.project.name || 'Understand-Binary Explorer'}</span>
              {graph?.project.binaryTarget && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
                  {graph.project.binaryTarget.format.toUpperCase()}
                </span>
              )}
            </h1>
            <p className="text-xs text-slate-400">
              {graph?.project.description || 'Decompiled Architecture Knowledge Graph'}
            </p>
          </div>
        </div>

        {/* Search & Subsystem Layer Filter */}
        <div className="flex items-center gap-3">
          {graph && (
            <select
              value={selectedLayer}
              onChange={(e) => setSelectedLayer(e.target.value)}
              className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Subsystems ({graph.layers.length})</option>
              {graph.layers.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          )}

          <input
            type="text"
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search symbols, APIs, IPC..."
            className="px-3 py-1.5 bg-slate-800/80 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-56"
          />

          <button
            onClick={() => networkRef.current?.fit({ animation: true })}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg border border-slate-700 transition"
          >
            Reset
          </button>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="text-right">
            <span className="text-slate-400">Nodes: </span>
            <span className="text-cyan-400">{graph?.nodes.length || 0}</span>
            <span className="text-slate-400"> | Edges: </span>
            <span className="text-cyan-400">{graph?.edges.length || 0}</span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex flex-1 relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-slate-950/60 backdrop-blur z-30">
            <div className="text-sm font-medium text-cyan-400 animate-pulse">
              Loading binary architecture graph...
            </div>
          </div>
        )}

        {error && (
          <div className="absolute inset-0 flex items-center justify-center bg-slate-950/80 z-30">
            <div className="p-6 max-w-md bg-slate-900 border border-red-500/30 rounded-xl text-center space-y-3">
              <div className="text-red-400 font-semibold text-sm">Failed to connect to Understand-Binary API</div>
              <p className="text-xs text-slate-400">{error}</p>
              <p className="text-xs text-slate-500">Run <code className="text-cyan-400 font-mono">ub analyze &lt;binary&gt; --dashboard</code> in your terminal.</p>
            </div>
          </div>
        )}

        {/* Canvas */}
        <div ref={containerRef} className="w-full h-full bg-[#0B0F17]" />

        {/* Evidence & Technical Inspector Drawer */}
        <aside className="w-96 border-l border-slate-800 bg-slate-900/90 backdrop-blur flex flex-col z-20 shrink-0">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Technical Inspector
            </h2>
            {selectedNode && (
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-mono">
                {selectedNode.type.toUpperCase()}
              </span>
            )}
          </div>

          <div className="p-5 flex-1 overflow-y-auto space-y-4">
            {selectedNode ? (
              <>
                <div>
                  <h3 className="text-base font-bold text-white break-all">{selectedNode.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{selectedNode.summary}</p>
                </div>

                {selectedNode.binaryMeta && (
                  <div className="space-y-3">
                    <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/60 text-xs space-y-1.5 font-mono">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Address:</span>
                        <span className="text-cyan-400">{selectedNode.binaryMeta.address || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Role:</span>
                        <span className="text-amber-400">{selectedNode.binaryMeta.role || 'general'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Exported:</span>
                        <span className="text-emerald-400">
                          {selectedNode.binaryMeta.isExported ? 'YES' : 'NO'}
                        </span>
                      </div>
                    </div>

                    <div>
                      <label className="text-xs font-semibold text-slate-400 block mb-1.5">
                        Decompiled / Pseudo-code
                      </label>
                      <pre className="p-3 bg-black/60 rounded-lg border border-slate-800 text-xs text-emerald-400 font-mono overflow-x-auto max-h-64 leading-relaxed">
                        {selectedNode.binaryMeta.pseudoCode || '// No pseudo-code extracted'}
                      </pre>
                    </div>
                  </div>
                )}

                {selectedNode.tags && selectedNode.tags.length > 0 && (
                  <div>
                    <label className="text-xs font-semibold text-slate-400 block mb-1.5">Tags</label>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedNode.tags.map((t) => (
                        <span
                          key={t}
                          className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs">
                Click any component, symbol, or API node on the graph to inspect decompiled code, memory addresses, and relationships.
              </div>
            )}

            {graph?.layers && graph.layers.length > 0 && (
              <div className="pt-4 border-t border-slate-800">
                <label className="text-xs font-semibold text-slate-400 block mb-2">
                  Architectural Layers ({graph.layers.length})
                </label>
                <div className="space-y-1.5">
                  {graph.layers.map((l) => (
                    <div
                      key={l.id}
                      onClick={() => setSelectedLayer(selectedLayer === l.id ? 'all' : l.id)}
                      className={`p-2 rounded text-xs cursor-pointer border transition flex justify-between items-center ${
                        selectedLayer === l.id
                          ? 'bg-cyan-950/60 border-cyan-800 text-cyan-300'
                          : 'bg-slate-800/40 border-slate-800 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <span className="font-medium">{l.name}</span>
                      <span className="text-slate-500 font-mono text-[11px]">{l.nodeIds.length} items</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}
