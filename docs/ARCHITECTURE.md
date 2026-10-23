# Understand-Binary: Production Architecture Documentation

## 1. System Overview

Understand-Binary is a modular reverse-engineering and architecture visualization platform designed for software comprehension, security analysis, and AI-assisted investigation.

```text
Target Binary (.apk, .asar, Mach-O, ELF, PE)
        │
        ▼
[1] Ingestion & Extraction Engine (@understand-binary/core-re)
        ├── Magic Byte & Header Inspector (Bitness, Endianness, Arch, SHA-256)
        ├── Instruction Disassembler (llvm-objdump / otool via safeExec)
        ├── Call & Branch Target Decoder (call, bl, jmp, symbol stubs)
        ├── Section & Segment Extractor
        └── High-Entropy String Classifier (URLs, SQL, Tokens, Filepaths)
        │
        ▼
[2] Bridge Normalization Layer (@understand-binary/bridge)
        ├── Runtime Noise Filter (_start, dyld_stub_binder, __libc_csu_init)
        ├── Architectural Subsystem Classifier (UI, Core, Storage, Network, Security, IPC)
        ├── Provenance Annotator (verified_fact vs heuristic_inference)
        └── Unified Architecture IR (ArchitectureIR)
        │
        ├─────────────────────────────┬──────────────────────────┐
        ▼                             ▼                          ▼
[3] Knowledge Graph Engine   [4] Security Scanner       [5] AI Investigator
   (@understand-binary/         (@understand-binary/       (@understand-binary/
    graph-engine)                investigator)              investigator)
        │                             │                          │
        ├── knowledge-graph.json      ├── security-findings.json ├── Multi-Provider LLM
        └── Guided Tour Pipeline      └── Remediation Rules      ├── BFS Call Path Solver
        │                             │                          └── MCP Stdio Server
        └─────────────────────────────┼──────────────────────────┘
                                      ▼
                        [6] CLI & Server (@understand-binary/cli)
                                      ├── `ub analyze <target>`
                                      ├── `ub serve [dir]`
                                      ├── `ub mcp [dir]`
                                      └── `ub investigate <question>`
                                      │
                                      ▼
                        [7] Interactive Web Dashboard
                                      ├── 2D/3D Force-Directed Graph
                                      ├── Execution Call Path Explorer
                                      ├── Security Findings Drawer
                                      ├── Disassembly Instruction Viewer
                                      └── AI Investigation Workspace
```

---

## 2. Key Architectural Guarantees

1. **Hostile Input Safety**: Binaries and strings are treated as completely untrusted input. Native tools are executed strictly using parameter arrays via `safeExec` (`child_process.execFile`), preventing shell interpolation vulnerabilities.
2. **Provenance Distinction**: Every symbol and relationship carries a `provenance` tag (`verified_fact`, `heuristic_inference`, or `llm_hypothesis`). Original binary addresses and symbol names are never overwritten by AI inferences.
3. **Evidence-First AI Reasoning**: The `BinaryInvestigator` agent executes real tool calls (`list_functions`, `search_strings`, `get_disassembly`, `find_call_path`, `get_security_findings`) and cites verified addresses and instruction bytes in every response.
4. **Offline Autonomy**: All features (disassembly, call graph construction, security findings, call path tracing, and rule-based investigations) function deterministically offline without requiring cloud API keys.
5. **Model Context Protocol (MCP)**: Native stdio transport compliant with the MCP specification, enabling AI agents (Antigravity, Claude Desktop, Cursor) to directly query the analysis database.
