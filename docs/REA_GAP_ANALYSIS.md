# Understand-Binary vs. REA: Gap Analysis & Feature Matrix

**Reference System:** REA (`morluto/rea`, v6.4.0)  
**Target System:** Understand-Binary (`devanshvpurohit/understand-binary`)

---

## 1. Architectural Philosophy Comparison

| Dimension | REA (`morluto/rea`) | Understand-Binary (Current) | Understand-Binary (Production Target) |
| :--- | :--- | :--- | :--- |
| **Primary Interaction** | MCP Server & Headless CLI for Agent consumption | CLI & Web Dashboard | **Dual**: Full MCP Server + CLI + Rich Interactive Web Dashboard |
| **Binary Disassembly Engine** | Hopper, Ghidra, IDA Pro, JADX, Apktool, Wakaru | `nm`, `otool -L`, regex, basic ASAR/APK unpacker | **Multi-tier**: Host LLVM/otool/objdump + Hopper/Ghidra headless adapters + Bytecode decoders |
| **Call Graph & Xrefs** | Rich instruction-level cross-references and caller/callee trees | Superficial (nm stubs, only 4 mock edges on stripped files) | **Verified Instruction Tracing**: Extracts actual call targets (`call`, `bl`, `jmp`, symbol stubs) |
| **Data Representation** | Linear Evidence Ledger + MCP Resources | Hierarchical Knowledge Graph (`knowledge-graph.json`) | **Evidence-Backed Knowledge Graph**: Graph nodes paired with byte-accurate Evidence Ledger |
| **AI Investigation** | External Agent invokes REA tools | None (User browses static graph) | **Embedded AI Agent + MCP**: Multi-model orchestrator with evidence citation + MCP server |
| **Visual Exploration** | Minimal / None (terminal text only) | Vis-Network 2D Graph | **Advanced Dual-Pane UI**: Subsystem clustering + Call path tracer + Disassembly inspector + AI Chat |

---

## 2. Feature Matrix & Gap Analysis

| Feature | REA Status | Understand-Binary Status | Gap Severity | Proposed Implementation | Dependencies | Acceptance Criteria |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| **Format Detection** | Comprehensive (Mach-O, PE, ELF, DEX, ASAR, WASM, EVM) | Basic magic-byte checks | **Low** | Expand magic-byte table with endianness, bitness, and sub-architecture detection. | Pure Node.js `Buffer` | Accurately identifies 32/64-bit, endianness, entrypoint offset. |
| **Native Disassembly** | Deep (via Hopper, Ghidra, IDA) | None (only symbol names) | **Critical** | Implement `NativeDisassemblyEngine` using `llvm-objdump -d` / `otool -tv` with instruction stream parser. | Host `objdump`/`otool` | Disassembles real functions into ordered instructions with opcodes and mnemonic operands. |
| **Call Graph & Xrefs** | Full Xref engine with caller/callee resolution | Hardcoded / empty for stripped binaries | **Critical** | Parse branch/call instructions (`call`, `bl`, `b`, `jmp`) and link to target symbols/stubs. | Disassembly stream | Verified caller/callee list for any disassembled function. |
| **Decompilation** | Decompiler pseudocode via Ghidra / Hopper | None | **High** | Implement Hopper CLI (`hopper -e`) and Ghidra headless script adapters; graceful fallback to annotated disassembly when absent. | Hopper / Ghidra (optional) | Displays real decompiled C/pseudo-code when engine installed, or clear "Decompiler Unavailable" indicator. |
| **Electron / ASAR** | ASAR unpacking + Wakaru unbundling | ASAR unpacker + regex function detection | **Medium** | Enhance AST parser to extract exact IPC event signatures, context isolation bindings, and routes. | `@babel/parser` or Tree-sitter | Maps full IPC request/response flow across main & renderer contexts. |
| **Android APK** | JADX decompilation + manifest decode | Zip entry listing + mock classes | **High** | Real Android Manifest XML parser (binary AXML decoder) + DEX header parser. | Pure TS AXML decoder | Recovers real package name, activities, permissions, and DEX class names. |
| **MCP Server Interface** | 100+ Model Context Protocol tools | None | **Critical** | Implement standard MCP stdio server (`ub mcp`) exposing `list_procedures`, `procedure_assembly`, `procedure_callers`, `procedure_callees`, `xrefs`, `search_strings`, `binary_overview`. | `@modelcontextprotocol/sdk` | External AI agents (Antigravity, Claude Desktop, Cursor) can query Understand-Binary directly via MCP. |
| **AI Investigation Engine** | Relies on external agent driving MCP | None | **High** | Implement `ai-investigator` package supporting Gemini, Claude, OpenAI, and local Ollama with structured tool calling and evidence citations. | AI SDKs / Fetch | Answers queries (e.g. "Trace network requests") using real tool calls and citing specific addresses. |
| **Evidence vs Hypothesis** | Strict evidence records | Graph mixes inferred subsystems with raw symbols | **Medium** | Explicitly tag all graph nodes and findings with provenance: `verified_fact` vs `heuristic_inference` vs `llm_hypothesis`. | Graph Schema | Every claim in UI shows provenance badge and source address. |
| **Security Findings Scanner** | Basic pattern matching | None | **Medium** | Static pattern scanner for dangerous APIs (`strcpy`, `gets`, `system`, insecure crypto, hardcoded JWT/private keys). | Pure TS analyzer | Flags suspicious functions with category, severity, and evidence citations. |
| **Execution Path Tracer** | Manual xref traversal | None | **High** | Dijkstra / BFS path-finding algorithm on the call graph to find paths between Function A and Function B. | Graph Engine | Displays verified static call path between two addresses/symbols. |
| **Test Suite** | Comprehensive vitest suite with fixtures | Zero tests | **Critical** | Write automated unit and integration tests covering detectors, disassembly parser, normalizer, and graph synthesis. | `node:test` / `vitest` | All tests pass in CI/local runs. |

---

## 3. Implementation Order

1. **Step 1: Security & Robust Ingestion (P0)**
   - Eliminate unsafe shell execs; introduce `safeExec` using `child_process.execFile`.
   - Add real instruction-level native disassembler (`NativeDisassemblyEngine`) parsing instructions, opcodes, and calls.
   - Add real AXML / DEX header parser for Android.
2. **Step 2: Verified Call Graphs & Cross-References (P0)**
   - Connect instruction jump/call targets to build genuine caller/callee trees and cross-references.
   - Tag provenance (`verified_fact` vs `heuristic`).
3. **Step 3: MCP Server (`ub mcp`) (P1)**
   - Expose the REA-standard inspection tools over MCP stdio protocol.
4. **Step 4: AI Investigation Engine & Multi-Provider Abstraction (P1)**
   - Implement autonomous investigation loop with tool calling, context management, and evidence citation.
5. **Step 5: Security Findings & Call Path Exploration (P2)**
   - Static security analyzer and graph shortest-path solver.
6. **Step 6: Dashboard Upgrade (P2)**
   - Dual-view UI with Call Path Tracer, Security Findings tab, and AI Investigation Chat drawer.
7. **Step 7: Automated Test Corpus & Verification (P0-P2)**
   - Real benign test binaries and end-to-end integration tests.
