# Understand-Binary: Security & Threat Model

## 1. Threat Model & Hostile Input Posture

Reverse engineering platforms ingest binaries that may be corrupted, obfuscated, maliciously crafted, or hostile. Understand-Binary enforces strict boundary controls to protect the host environment.

---

## 2. Security Boundaries Enforced

### 2.1 Command Execution Safety
* **Elimination of Shell Interpolation**: All external invocations (`objdump`, `otool`, `unzip`, `nm`) are executed exclusively using `child_process.execFile` with explicit argument arrays. Shell string concatenations (`execSync("tool " + path)`) are strictly prohibited.
* **Execution Timeouts**: Every subprocess execution is bounded by a strict default timeout (15,000 ms) via `safeExec` to prevent hanging processes caused by malicious binaries.
* **Buffer Overflow Prevention**: `maxBuffer` limits are enforced on child process pipes (default 20MB-30MB) to prevent memory exhaustion during disassembly.

### 2.2 Input Validation & Path Traversal Guards
* Paths supplied to CLI and API routes are normalized using `path.resolve` and verified for existence prior to file operations.
* File extension spoofing is mitigated by reading initial magic bytes directly from file headers rather than relying on filename extensions.

### 2.3 Secret and Credential Protection
* AI provider API keys (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) reside exclusively in backend environment memory and are never bundled into client-side Vite builds or serialized into `knowledge-graph.json`.
* Extracted tokens, JWTs, and passwords discovered inside target binaries are classified as `key_or_token` and redacted in high-level summaries.

### 2.4 Sandboxing Dynamic Execution
* Understand-Binary performs **static analysis** by default.
* Target binaries are **never executed directly on the host system**.
* Disassembly and symbol resolution are performed using disassemblers (`otool`, `llvm-objdump`), not through direct execution.

---

## 3. Recommended Production Hardening

For multi-tenant or web-hosted deployments:
1. Run analysis workers inside unprivileged Docker containers or isolated firejailed sandboxes.
2. Disable network egress from analysis worker containers.
3. Apply OS-level resource limits (`ulimit -v`, cgroups) to cap memory and CPU usage per analysis job.
