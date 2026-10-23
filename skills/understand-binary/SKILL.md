---
name: understand-binary
description: Reverse engineer any binary executable (Mach-O, ELF, PE, Electron ASAR, Android APK), reconstruct its software architecture into an interactive knowledge graph, scan for security findings, trace execution call paths, and investigate behavior with evidence-backed AI.
argument-hint: ["[binary_path] [--dashboard] [--force] [--port <port>] [--investigate <question>]"]
---

# /understand-binary

Ingest and reverse engineer a compiled binary application or package, normalize its symbols and subsystems, decode assembly instructions, scan for static vulnerabilities, and generate an interactive technical architecture knowledge graph.

## Usage

```bash
/understand-binary <binary_path> [--dashboard] [--force]
```

Or investigate directly:
```bash
/understand-binary --investigate "Where is authentication or network handled?"
```

## Options

- `<binary_path>`: Path to a binary file (`.asar`, `.apk`, Mach-O executable, ELF, PE `.exe`/`.dll`, or JS bundle).
- `--dashboard`: Automatically launch the interactive architecture visualizer in the browser (default `http://localhost:3000`).
- `--force`: Force complete re-analysis, bypassing the content-addressable SHA-256 cache.
- `--output <dir>`: Directory where `knowledge-graph.json`, `architecture-ir.json`, and `security-findings.json` are written (defaults to `.ub/`).
- `--investigate <question>`: Run an autonomous evidence-first investigation answering a technical question with verified addresses and instruction bytes.
- `--port <port>`: Port to serve the visualization dashboard (defaults to 3000).

---

## Antigravity & OpenCode Integration

### 1. In Antigravity (Chat or Terminal)
* **Slash Command**: Run `/understand-binary /bin/ls --dashboard` directly in chat.
* **MCP Server**: Registered in `~/.gemini/config/mcp_config.json`. Antigravity can invoke tools:
  - `get_analysis_status()`
  - `list_functions(role)`
  - `get_disassembly(addressOrName)`
  - `get_callers(addressOrName)`
  - `get_callees(addressOrName)`
  - `search_strings(pattern, classification)`
  - `find_call_path(source, target)`
  - `get_security_findings()`

### 2. In OpenCode (CLI & Tasks)
* **Skill Auto-Discovery**: OpenCode automatically discovers this skill via `~/.agents/skills/understand-binary`.
* **CLI Invocation**:
  ```bash
  ub analyze /path/to/binary --dashboard
  ub investigate "Trace execution flow from main to network send"
  ub mcp .ub
  ```
