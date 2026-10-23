import type {
  AnalysisCoverage,
  ProvenanceKind,
  Instruction,
  Section,
} from '@understand-binary/core-re';

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
  instructions?: Instruction[];
  provenance: ProvenanceKind;
}

export interface RelationshipIR {
  sourceId: string;
  targetId: string;
  type: 'calls' | 'imports' | 'ipc_bridge' | 'data_flow' | 'contains' | 'implements';
  label?: string;
  confidence: number;
  provenance: ProvenanceKind;
}

export interface ArchitectureIR {
  targetInfo: {
    fileName: string;
    filePath: string;
    fileSize: number;
    format: string;
    arch: string;
    bitness: 32 | 64 | 'unknown';
    endianness: 'little' | 'big' | 'unknown';
    platform: string;
    isStripped: boolean;
    sha256: string;
  };
  sections: Section[];
  subsystems: SubsystemIR[];
  components: ComponentIR[];
  symbols: SymbolIR[];
  relationships: RelationshipIR[];
  strings: { value: string; classification: string }[];
  coverage: AnalysisCoverage;
}
