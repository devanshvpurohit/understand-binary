# Understand-Binary: Implementation Audit

**Audit Date:** October 2026  
**Auditor:** Principal Reverse-Engineering Engineer & Systems Architect  
**Codebase Version:** 0.1.0-alpha  
**Scope:** Full repository review of `@understand-binary/*`

---

## 1. Executive Summary

Understand-Binary was established to bridge binary reverse-engineering engines with an interactive architectural knowledge graph. The repository currently possesses an initial working skeleton featuring basic format detection, superficial symbol parsing (`nm`, `otool -L`), ASAR/APK archive inspection, a bridge normalizer, a graph synthesizer adhering to Understand-Anything's `knowledge-graph.json` schema, and an interactive React 19 dashboard.

However, significant gaps exist between this foundation and a production-grade reverse engineering platform:
1. **Shallow Native Analysis**: Disassembly and cross-reference extraction are missing or hardcoded to superficial mocks when symbols are missing. Native instruction-level analysis (opcodes, basic blocks, control flow graphs, call instructions) does not extract real callers/callees from raw code.
2. **Absence of Real Automated Tests**: Test scripts execute `node --test dist/**/*.test.js`, but zero test files exist.
3. **No AI-Powered Investigation Engine**: The CLI and server do not possess an agentic reasoning loop, multi-provider LLM abstraction, or tool-calling orchestration with evidence citations.
4. **No MCP Server Implementation**: The Model Context Protocol (MCP) server is not exposed for external AI coding agents.
5. **Security & Sandboxing Deficits**: External CLI execution (`otool`, `objdump`, `unzip`) uses shell template strings rather than safe argument arrays, risking command injection on crafted filenames.
6. **No Real Persistence Layer**: Projects and analysis runs are stored as single JSON files on disk without project versioning, content hashing (SHA256), or incremental caching.

---

## 2. Component-by-Component Audit

### 2.1 `@understand-binary/core-re`
* **Status:** Implemented but Incomplete & Superficial.
* **Implemented:**
  * Magic byte detection for Mach-O, ELF, PE, APK/ZIP, ASAR (`src/detector.ts`).
  * Regex-based string extraction for URLs, paths, SQL, and keys (`src/strings.ts`).
  * Basic symbol listing via `nm` and dynamic libraries via `otool -L` / `objdump -p` (`src/engines/native.ts`).
  * Uncompressed ASAR JSON header traversal and AST/regex function & IPC discovery (`src/engines/electron.ts`).
  * APK zip entry traversal for `.so` libraries and basic DEX class structure (`src/engines/android.ts`).
* **Incomplete / Critical Deficiencies:**
  * **No Real Disassembly & Control Flow**: Functions in stripped binaries or functions without `nm` symbol entries fall back to a hardcoded `_main` stub.
  * **No Call Instruction Decoding**: Caller/callee relationships in native binaries are not parsed from `call`, `bl`, or `jmp` instructions.
  * **No Real Decompilation Bridge**: Does not leverage Ghidra headless, Hopper CLI, or Rizin for decompiled pseudocode.
  * **Unsafe Process Execution**: Uses `execSync(`otool -L "${filePath}"`)` which is vulnerable to command injection if filenames contain shell metacharacters.

### 2.2 `@understand-binary/bridge`
* **Status:** Implemented (Functional for metadata).
* **Implemented:**
  * Noise filtering for runtime startup routines (`_start`, `dyld_stub_binder`, `__libc_csu_init`).
  * Subsystem classification based on heuristic role detection (`ui`, `network`, `storage`, `security`, `ipc`, `core`).
  * Translation of raw symbols and modules into `ArchitectureIR`.
* **Incomplete / Critical Deficiencies:**
  * Does not calculate basic block metrics, cyclomatic complexity, or graph centrality.
  * Lacks explicit provenance tracking (differentiating hard binary facts from heuristic inferences).

### 2.3 `@understand-binary/graph-engine`
* **Status:** Implemented (Adheres to Understand-Anything schema).
* **Implemented:**
  * Zod schema for `GraphNode`, `GraphEdge`, `Layer`, `TourStep`, and `KnowledgeGraph`.
  * Node generation for subsystems, components, functions, and endpoints.
  * Guided tour generation.
* **Incomplete / Critical Deficiencies:**
  * Lacks incremental graph update capabilities.
  * Does not output formal JSON-LD or reproducible evidence hashes.

### 2.4 `@understand-binary/dashboard`
* **Status:** Implemented (Functional UI).
* **Implemented:**
  * React 19 + Vite + Tailwind CSS.
  * Vis-network force-directed 2D graph visualizer with node selection and search.
  * Subsystem layer filtering.
  * Technical inspector side drawer showing function metadata and pseudo-code.
* **Incomplete / Critical Deficiencies:**
  * Graph cannot handle 10,000+ nodes efficiently without virtualization or hierarchical clustering.
  * No chat/investigation workspace UI connected to an LLM.
  * No visual call-tree path tracer between two user-selected nodes.

### 2.5 `@understand-binary/cli`
* **Status:** Implemented.
* **Implemented:**
  * Commander CLI with `analyze` and `serve` commands.
  * Built-in HTTP static server and API endpoints (`/api/graph`, `/api/ir`).
* **Incomplete / Critical Deficiencies:**
  * Missing `ub mcp` command to run as a Model Context Protocol server.
  * Missing `ub investigate` command.
  * Does not support background asynchronous jobs or progress reporting.

---

## 3. Broken Integrations & Reliability Risks

1. **Host Dependency Drift**: `otool` only exists on macOS; on Linux, `objdump` and `readelf` must be used with sanitized argument arrays (`execFile`).
2. **Missing Input Sanitization**: Path traversal or malicious filenames passed to `analyze` can break execution.
3. **No Timeout Protection**: Analyzing an enormous binary (>500MB) can freeze the Node.js process without memory or CPU bounds.

---

## 4. Priority Roadmap for Production Grade

1. **P0 (Foundation & Reliability)**:
   - Replace all unsafe `execSync` with sanitized `execFile` using argument arrays.
   - Implement real native disassembly and call instruction decoding (ARM64 `bl`/`b`, x86_64 `call`/`jmp`) using `llvm-objdump` / `otool` / native parser to recover verified caller/callee graphs.
   - Build a comprehensive automated test suite with real test binary fixtures.
2. **P1 (REA-Grade Analysis & MCP)**:
   - Implement native Hopper/Ghidra/Rizin provider adapters.
   - Implement full MCP server (`ub mcp`) exposing official REA-compatible tools (`list_procedures`, `procedure_assembly`, `procedure_callers`, `procedure_callees`, `xrefs`, `search_strings`, `binary_overview`).
   - Implement AI Investigation Engine with multi-provider support (Gemini, Claude, OpenAI, Ollama) and strict evidence citation.
3. **P2 (Visual Differentiation & Security Findings)**:
   - Implement security findings scanner (unsafe memory functions, hardcoded keys, cleartext HTTP, weak crypto).
   - Add Call Path Explorer (trace execution path from Function A to Function B) in both CLI and Dashboard.
   - Add Interactive Chat Investigation tab in Dashboard.
