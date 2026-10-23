import type { ArchitectureIR } from '@understand-binary/bridge';
import type {
  KnowledgeGraph,
  GraphNode,
  GraphEdge,
  Layer,
  TourStep,
} from './schema.js';

export function synthesizeKnowledgeGraph(ir: ArchitectureIR): KnowledgeGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const layers: Layer[] = [];
  const tour: TourStep[] = [];

  // Track node IDs to avoid duplicate edges or missing references
  const nodeIds = new Set<string>();

  // 1. Create Subsystem / Layer Nodes
  for (const sub of ir.subsystems) {
    const subNodeId = `layer_${sub.id}`;
    nodeIds.add(subNodeId);
    nodes.push({
      id: subNodeId,
      type: 'service',
      name: sub.name,
      summary: sub.description,
      tags: ['subsystem', sub.role, 'architecture'],
      complexity: 'moderate',
    });

    const layerNodeIds: string[] = [subNodeId];

    // 2. Create Component Nodes inside Subsystems
    for (const compId of sub.componentIds) {
      const comp = ir.components.find((c) => c.id === compId);
      if (!comp) continue;

      nodeIds.add(comp.id);
      layerNodeIds.push(comp.id);

      nodes.push({
        id: comp.id,
        type: comp.type === 'ipc_bridge' ? 'endpoint' : 'module',
        name: comp.name,
        filePath: comp.filePath,
        summary: `Component '${comp.name}' responsible for ${sub.role} tasks.`,
        tags: [comp.type, sub.role],
        complexity: comp.symbolIds.length > 10 ? 'complex' : 'simple',
      });

      // Edge from Subsystem -> Component
      edges.push({
        source: subNodeId,
        target: comp.id,
        type: 'contains',
        direction: 'forward',
        weight: 0.8,
        description: `Subsystem contains ${comp.name}`,
      });
    }

    layers.push({
      id: sub.id,
      name: sub.name,
      description: sub.description,
      nodeIds: layerNodeIds,
    });
  }

  // 3. Create Function / Symbol Nodes
  for (const sym of ir.symbols) {
    nodeIds.add(sym.id);
    nodes.push({
      id: sym.id,
      type: 'function',
      name: sym.name,
      summary: sym.isImported
        ? `External imported symbol: ${sym.name}`
        : `Decompiled routine at ${sym.address || 'native'} [${sym.role}]`,
      tags: ['symbol', sym.role, sym.isExported ? 'exported' : 'internal'],
      complexity: sym.callees.length > 3 ? 'complex' : 'simple',
      binaryMeta: {
        address: sym.address,
        isExported: sym.isExported,
        isImported: sym.isImported,
        role: sym.role,
        pseudoCode: sym.codeSnippet,
      },
    });

    // Edge from Component -> Symbol
    if (nodeIds.has(sym.componentId)) {
      edges.push({
        source: sym.componentId,
        target: sym.id,
        type: 'contains',
        direction: 'forward',
        weight: 0.7,
        description: `Defines symbol ${sym.name}`,
      });
    }
  }

  // 4. Create Inter-Symbol / Inter-Component Relationships
  for (const rel of ir.relationships) {
    // Only connect if both endpoints exist in the graph
    if (nodeIds.has(rel.sourceId) && nodeIds.has(rel.targetId)) {
      edges.push({
        source: rel.sourceId,
        target: rel.targetId,
        type: rel.type === 'ipc_bridge' ? 'routes' : rel.type === 'imports' ? 'imports' : 'calls',
        direction: 'forward',
        weight: rel.confidence,
        description: rel.label || `${rel.type} relationship`,
      });
    }
  }

  // 5. Generate Guided Architecture Tour
  let tourOrder = 1;
  const entryNodes = nodes.filter((n) => n.binaryMeta?.isExported || n.name.includes('main') || n.name.includes('Activity'));
  if (entryNodes.length > 0) {
    const ids = entryNodes.slice(0, 5).map((n) => n.id);
    tour.push({
      order: tourOrder++,
      title: 'Entry Points & Public Surface',
      description: 'The binary executable entrypoints, exported hooks, or activity lifecycles.',
      nodeIds: ids,
      targetNodeIds: ids,
    });
  }

  const subNodes = nodes.filter((n) => n.type === 'service');
  if (subNodes.length > 0) {
    const ids = subNodes.map((n) => n.id);
    tour.push({
      order: tourOrder++,
      title: 'Core Architectural Subsystems',
      description: 'High-level functional layers discovered across the reversed binary.',
      nodeIds: ids,
      targetNodeIds: ids,
    });
  }

  const ipcNodes = nodes.filter((n) => n.tags.includes('ipc') || n.type === 'endpoint');
  if (ipcNodes.length > 0) {
    const ids = ipcNodes.slice(0, 6).map((n) => n.id);
    tour.push({
      order: tourOrder++,
      title: 'IPC & Cross-Context Channels',
      description: 'Inter-process boundaries connecting renderer, workers, or system services.',
      nodeIds: ids,
      targetNodeIds: ids,
    });
  }

  // Infer languages and frameworks
  const hasLua = nodes.some((n) => n.id.includes('.lua') || n.filePath?.endsWith('.lua') || n.summary.includes('Lua'));
  const hasJs = nodes.some((n) => n.filePath?.endsWith('.js') || n.tags.includes('ipc'));
  const languages: string[] = hasLua
    ? ['Lua', 'C++', 'Mach-O']
    : hasJs
    ? ['JavaScript', 'TypeScript', 'C++']
    : ['C/C++', 'Assembly', 'Mach-O'];

  const frameworks: string[] = hasLua
    ? ['LÖVE2D', 'Cocoa', 'LuaJIT']
    : hasJs
    ? ['Electron', 'Node.js', 'Chromium']
    : ['Cocoa', 'Darwin Runtime'];

  return {
    version: '1.0.0',
    kind: 'codebase',
    project: {
      name: ir.targetInfo.fileName,
      languages,
      frameworks,
      description: `Reconstructed technical architecture for ${ir.targetInfo.fileName} (${ir.targetInfo.format}, ${ir.targetInfo.arch})`,
      analyzedAt: new Date().toISOString(),
      gitCommitHash: 'binary-reconstruction',
      binaryTarget: ir.targetInfo,
    },
    nodes,
    edges,
    layers,
    tour,
  };
}
