---
name: understand-binary
description: Reverse engineer a binary application (Native Mach-O/ELF/PE, Electron ASAR/JS, Android APK) and generate an interactive technical architecture knowledge graph and visual dashboard.
argument-hint: ["[binary_path] [--dashboard] [--port <port>] [--output <dir>]"]
---

# /understand-binary

Reverse engineer a compiled, packaged, or shipped application binary, normalize its symbols and subsystems, and generate an interactive technical architecture knowledge graph.

## Usage

```bash
/understand-binary <binary_path> [--dashboard]
```

## Options

- `<binary_path>`: Path to a binary file (`.asar`, `.apk`, Mach-O executable, ELF, PE `.exe`/`.dll`, or JS bundle).
- `--dashboard`: Automatically launch the interactive architecture explorer in the browser.
- `--output <dir>`: Directory where `knowledge-graph.json` and `architecture-ir.json` will be written (defaults to `.ub/`).
- `--port <port>`: Port to serve the visualization dashboard (defaults to 3000).

## Execution Steps

1. Ingest target with `@understand-binary/core-re`:
   - Detect binary format and magic bytes.
   - Extract symbols, dynamic library dependencies, decompiled routines, and high-entropy strings.
   - Detect cross-boundary communication (IPC channels, Android intents, native bindings).
2. Run `@understand-binary/bridge`:
   - Filter linker/CRT boilerplate symbols (`_start`, `__libc_csu_init`, `dyld_stub_binder`).
   - Map symbols into functional Subsystems (UI, Core Logic, Cryptography/Security, Network, Storage, IPC).
3. Synthesize `@understand-binary/graph-engine`:
   - Generate `knowledge-graph.json` compliant with the Understand-Anything schema.
4. Launch Visual Explorer (if `--dashboard` specified or via `ub serve`):
   - Interactive 2D/3D force-directed architecture graph.
   - Real-time Technical Inspector with decompiled pseudo-code, memory offsets, and xrefs.
