import type { BinaryAnalysisResult } from '@understand-binary/core-re';
import type {
  ArchitectureIR,
  SubsystemIR,
  ComponentIR,
  SymbolIR,
  RelationshipIR,
} from './types.js';
import { isNoiseSymbol } from './filter.js';

export function normalizeBinaryAnalysis(result: BinaryAnalysisResult): ArchitectureIR {
  const subsystemsMap = new Map<string, SubsystemIR>();
  const componentsMap = new Map<string, ComponentIR>();
  const symbols: SymbolIR[] = [];
  const relationships: RelationshipIR[] = [];

  // Helper to ensure a subsystem exists
  const getOrCreateSubsystem = (
    id: string,
    name: string,
    role: SubsystemIR['role'],
    desc: string
  ): SubsystemIR => {
    if (!subsystemsMap.has(id)) {
      subsystemsMap.set(id, {
        id,
        name,
        description: desc,
        role,
        componentIds: [],
      });
    }
    return subsystemsMap.get(id)!;
  };

  // Helper to ensure a component exists
  const getOrCreateComponent = (
    id: string,
    name: string,
    subsystemId: string,
    type: ComponentIR['type'],
    filePath?: string
  ): ComponentIR => {
    if (!componentsMap.has(id)) {
      componentsMap.set(id, {
        id,
        name,
        subsystemId,
        type,
        symbolIds: [],
        filePath,
      });
      const sub = subsystemsMap.get(subsystemId);
      if (sub && !sub.componentIds.includes(id)) {
        sub.componentIds.push(id);
      }
    }
    return componentsMap.get(id)!;
  };

  // 1. Process Functions & Map to Components/Subsystems
  for (const fn of result.functions) {
    if (isNoiseSymbol(fn.name)) continue;

    const rawRole = fn.detectedRole || 'core';
    let subId = 'core_subsystem';
    let subName = 'Core Logic & Runtime';
    let role: SubsystemIR['role'] = 'core';

    if (rawRole === 'ui') {
      subId = 'ui_subsystem';
      subName = 'User Interface & Presentation';
      role = 'ui';
    } else if (rawRole === 'network') {
      subId = 'network_subsystem';
      subName = 'Networking & API Clients';
      role = 'network';
    } else if (rawRole === 'storage') {
      subId = 'storage_subsystem';
      subName = 'Persistence & Storage';
      role = 'storage';
    } else if (rawRole === 'security' || rawRole === 'cryptography' || rawRole === 'auth') {
      subId = 'security_subsystem';
      subName = 'Security & Cryptography';
      role = 'security';
    } else if (rawRole === 'ipc') {
      subId = 'ipc_subsystem';
      subName = 'Inter-Process Communication';
      role = 'ipc';
    }

    getOrCreateSubsystem(subId, subName, role, `Manages ${role} related operations.`);

    const compId = fn.moduleName ? `comp_${fn.moduleName.replace(/[^a-zA-Z0-9_]/g, '_')}` : 'comp_main';
    const compName = fn.moduleName || 'MainModule';
    const comp = getOrCreateComponent(compId, compName, subId, 'module');

    const symbolIR: SymbolIR = {
      id: fn.id,
      name: fn.name,
      componentId: compId,
      address: fn.address,
      isExported: fn.isExported,
      isImported: fn.isImported,
      role: fn.detectedRole || 'general',
      callers: fn.callers,
      callees: fn.callees,
      codeSnippet: fn.pseudoCode,
    };
    symbols.push(symbolIR);
    comp.symbolIds.push(fn.id);

    // Call relationships
    for (const callee of fn.callees) {
      relationships.push({
        sourceId: fn.id,
        targetId: callee,
        type: 'calls',
        confidence: 0.85,
      });
    }
  }

  // 2. Process IPC channels (Electron / OS IPC)
  if (result.ipcChannels.length > 0) {
    const ipcSub = getOrCreateSubsystem('ipc_subsystem', 'Inter-Process Communication', 'ipc', 'Bridges renderer and main execution contexts');
    for (const channel of result.ipcChannels) {
      const bridgeCompId = `ipc_channel_${channel.name.replace(/[^a-zA-Z0-9_]/g, '_')}`;
      getOrCreateComponent(bridgeCompId, `IPC: ${channel.name}`, ipcSub.id, 'ipc_bridge', channel.sourceFile);

      relationships.push({
        sourceId: channel.sourceFile ? `comp_${channel.sourceFile.replace(/[^a-zA-Z0-9_]/g, '_')}` : 'comp_main',
        targetId: bridgeCompId,
        type: 'ipc_bridge',
        label: channel.pattern,
        confidence: 0.95,
      });
    }
  }

  // 3. Process External APIs & Libraries
  if (result.externalAPIs.length > 0 || result.metadata.importedLibraries.length > 0) {
    const extSub = getOrCreateSubsystem('external_subsystem', 'External Dependencies & Libraries', 'external_api', 'Shared dynamic libraries and system frameworks');
    for (const lib of result.metadata.importedLibraries) {
      const libCompId = `ext_lib_${lib.replace(/[^a-zA-Z0-9_]/g, '_')}`;
      getOrCreateComponent(libCompId, lib, extSub.id, 'external_service');
      relationships.push({
        sourceId: 'comp_main',
        targetId: libCompId,
        type: 'imports',
        confidence: 1.0,
      });
    }
  }

  // Filter out empty subsystems
  const finalSubsystems = Array.from(subsystemsMap.values()).filter((s) => s.componentIds.length > 0);

  return {
    targetInfo: {
      fileName: result.metadata.fileName,
      filePath: result.metadata.filePath,
      format: result.metadata.format,
      arch: result.metadata.architecture,
      platform: result.metadata.platform,
      isStripped: result.metadata.isStripped,
    },
    subsystems: finalSubsystems,
    components: Array.from(componentsMap.values()),
    symbols,
    relationships,
    strings: result.strings.map((s) => ({ value: s.value, classification: s.classification })),
  };
}
