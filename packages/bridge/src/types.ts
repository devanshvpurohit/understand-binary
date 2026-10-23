export interface SubsystemIR {
  id: string;
  name: string;
  description: string;
  role: 'ui' | 'network' | 'storage' | 'security' | 'ipc' | 'core' | 'external_api';
  componentIds: string[];
}

export interface ComponentIR {
  id: string;
  name: string;
  subsystemId: string;
  type: 'module' | 'library' | 'class' | 'ipc_bridge' | 'external_service';
  symbolIds: string[];
  filePath?: string;
}

export interface SymbolIR {
  id: string;
  name: string;
  componentId: string;
  address?: string;
  isExported: boolean;
  isImported: boolean;
  role: string;
  callers: string[];
  callees: string[];
  codeSnippet?: string;
}

export interface RelationshipIR {
  sourceId: string;
  targetId: string;
  type: 'calls' | 'imports' | 'ipc_bridge' | 'data_flow' | 'contains' | 'implements';
  label?: string;
  confidence: number;
}

export interface ArchitectureIR {
  targetInfo: {
    fileName: string;
    filePath: string;
    format: string;
    arch: string;
    platform: string;
    isStripped: boolean;
  };
  subsystems: SubsystemIR[];
  components: ComponentIR[];
  symbols: SymbolIR[];
  relationships: RelationshipIR[];
  strings: { value: string; classification: string }[];
}
