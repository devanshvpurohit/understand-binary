import { z } from 'zod';

export const EdgeTypeSchema = z.enum([
  'imports', 'exports', 'contains', 'inherits', 'implements',
  'calls', 'subscribes', 'publishes', 'middleware',
  'reads_from', 'writes_to', 'transforms', 'validates',
  'depends_on', 'tested_by', 'configures',
  'related', 'similar_to',
  'deploys', 'serves', 'provisions', 'triggers',
  'migrates', 'documents', 'routes', 'defines_schema',
  'contains_flow', 'flow_step', 'cross_domain',
  'cites', 'contradicts', 'builds_on', 'exemplifies', 'categorized_under', 'authored_by',
  'instance_of', 'variant_of', 'uses_token',
]);

export const NodeTypeSchema = z.enum([
  'file', 'function', 'class', 'module', 'concept',
  'config', 'document', 'service', 'table', 'endpoint',
  'pipeline', 'schema', 'resource',
  'domain', 'flow', 'step',
  'article', 'entity', 'topic', 'claim', 'source',
  'page', 'screen', 'component', 'componentSet', 'instance', 'token',
]);

export const GraphNodeSchema = z.object({
  id: z.string(),
  type: NodeTypeSchema,
  name: z.string(),
  filePath: z.string().optional(),
  lineRange: z.tuple([z.number(), z.number()]).optional(),
  summary: z.string(),
  tags: z.array(z.string()),
  complexity: z.enum(['simple', 'moderate', 'complex']),
  languageNotes: z.string().optional(),
  // Extended binary metadata
  binaryMeta: z.object({
    address: z.string().optional(),
    isExported: z.boolean().optional(),
    isImported: z.boolean().optional(),
    role: z.string().optional(),
    pseudoCode: z.string().optional(),
  }).optional(),
}).passthrough();

export const GraphEdgeSchema = z.object({
  source: z.string(),
  target: z.string(),
  type: EdgeTypeSchema,
  direction: z.enum(['forward', 'backward', 'bidirectional']),
  description: z.string().optional(),
  weight: z.number().min(0).max(1),
});

export const LayerSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  nodeIds: z.array(z.string()),
});

export const TourStepSchema = z.object({
  order: z.number(),
  title: z.string(),
  description: z.string(),
  targetNodeIds: z.array(z.string()),
});

export const ProjectMetaSchema = z.object({
  name: z.string(),
  description: z.string(),
  analyzedAt: z.string(),
  gitCommitHash: z.string(),
  binaryTarget: z.object({
    fileName: z.string(),
    format: z.string(),
    arch: z.string(),
    isStripped: z.boolean(),
  }).optional(),
});

export const KnowledgeGraphSchema = z.object({
  version: z.string(),
  kind: z.enum(['codebase', 'knowledge', 'design']).default('codebase'),
  project: ProjectMetaSchema,
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  layers: z.array(LayerSchema),
  tour: z.array(TourStepSchema),
});

export type GraphNode = z.infer<typeof GraphNodeSchema>;
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;
export type Layer = z.infer<typeof LayerSchema>;
export type TourStep = z.infer<typeof TourStepSchema>;
export type KnowledgeGraph = z.infer<typeof KnowledgeGraphSchema>;
