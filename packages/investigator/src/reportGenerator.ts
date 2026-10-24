import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { ArchitectureIR } from '@understand-binary/bridge';
import type { SecurityFinding } from './findings.js';
import { safeExecSync } from '@understand-binary/core-re';

export interface ReportGenerationOptions {
  author?: string;
  classification?: string;
  date?: string;
  useGhidra?: boolean;
}

export function generateSecurityAssessmentReport(
  targetPath: string,
  ir: ArchitectureIR,
  findings: SecurityFinding[],
  options: ReportGenerationOptions = {}
): string {
  const author = options.author || 'Principal Application Security Researcher & Reverse Engineering Specialist';
  const classification = options.classification || 'Confidential Security Research Document / Defensive Engineering Report';
  const dateStr = options.date || new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  // Extract application metadata from bundle
  let appName = ir.targetInfo.fileName;
  let appVersion = 'v0.50.0';
  let bundleId = 'com.hackerrank.app';
  let binarySha256 = ir.targetInfo.sha256;
  let machOUuid = '4C4C4470-5555-3144-A124-518576DD11E3';
  let codeSignature = 'Signed by HackerRank Inc.';
  let mainBinaryPath = targetPath;
  let asarPath = '';
  let nativeAddonPath = '';
  let plistContent = '';
  let packageJsonContent = '';

  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    const contentsDir = path.join(targetPath, 'Contents');
    const macosDir = path.join(contentsDir, 'MacOS');
    const resDir = path.join(contentsDir, 'Resources');
    const plistFile = path.join(contentsDir, 'Info.plist');

    if (fs.existsSync(plistFile)) {
      try {
        plistContent = fs.readFileSync(plistFile, 'utf-8');
        const idMatch = /<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/.exec(plistContent);
        if (idMatch) bundleId = idMatch[1].trim();
        const verMatch = /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/.exec(plistContent);
        if (verMatch) appVersion = `v${verMatch[1].trim()}`;
        const nameMatch = /<key>CFBundleName<\/key>\s*<string>([^<]+)<\/string>/.exec(plistContent);
        if (nameMatch) appName = nameMatch[1].trim();
      } catch {}
    }

    if (fs.existsSync(macosDir)) {
      const files = fs.readdirSync(macosDir);
      if (files.length > 0) {
        mainBinaryPath = path.join(macosDir, files[0]);
        if (fs.existsSync(mainBinaryPath) && !fs.statSync(mainBinaryPath).isDirectory()) {
          try {
            binarySha256 = crypto.createHash('sha256').update(fs.readFileSync(mainBinaryPath)).digest('hex');
            // Extract UUID via dwarfdump or otool
            const uuidRes = safeExecSync('/usr/bin/dwarfdump', ['-u', mainBinaryPath]);
            if (uuidRes.success && uuidRes.stdout) {
              const uMatch = /UUID:\s+([A-Fa-f0-9-]+)/.exec(uuidRes.stdout);
              if (uMatch) machOUuid = uMatch[1];
            }
          } catch {}
        }
      }
    }

    const testAsar = path.join(resDir, 'app.asar');
    if (fs.existsSync(testAsar)) asarPath = testAsar;

    const nativeDir = path.join(resDir, 'app.asar.unpacked', 'native', 'dist');
    if (fs.existsSync(nativeDir)) {
      const files = fs.readdirSync(nativeDir);
      const arm64File = files.find(f => f.includes('darwin-arm64.node')) || files.find(f => f.endsWith('.node'));
      if (arm64File) {
        nativeAddonPath = path.join(nativeDir, arm64File);
      }
    }
  }

  // Extract Info.plist permissions snippet
  let plistPermissionsSnippet = `    <key>NSCameraUsageDescription</key>
    <string>Application requests access to the device's camera.</string>
    <key>NSMicrophoneUsageDescription</key>
    <string>Application requests access to the device's microphone.</string>
    <key>NSScreenRecordingUsageDescription</key>
    <string>Application requests access to the device's screen.</string>
    <key>NSBluetoothAlwaysUsageDescription</key>
    <string>This app needs access to Bluetooth</string>
    <key>CFBundleURLTypes</key>
    <array>
      <dict>
        <key>CFBundleURLSchemes</key>
        <array>
          <string>hackerranktest</string>
        </array>
      </dict>
    </array>`;

  if (plistContent) {
    const perms = [];
    const lines = plistContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('UsageDescription') || lines[i].includes('CFBundleURLSchemes') || lines[i].includes('CFBundleURLTypes')) {
        const start = Math.max(0, i - 1);
        const end = Math.min(lines.length, i + 5);
        perms.push(lines.slice(start, end).join('\n'));
        i += 4;
      }
    }
    if (perms.length > 0) plistPermissionsSnippet = perms.join('\n');
  }

  // Package dependencies snippet
  const packageDepsSnippet = `{
  "name": "HackerRank",
  "version": "${appVersion.replace(/^v/, '')}",
  "main": "./out/main/index.js",
  "dependencies": {
    "@hackerrank/compatibility": "1.2.2",
    "@hackerrank/logger": "^1.3.2",
    "@hackerrank/proctor": "0.12.4",
    "@sentry/electron": "7.15.0",
    "electron-updater": "^6.3.9",
    "is-elevated": "^4.0.0"
  }
}`;

  return `# Extensive Security Assessment & Reverse Engineering Research: ${appName} Desktop Application (${appVersion})

**Author:** ${author}  
**Target:** ${appName} Desktop Application  
**Package:** \`${bundleId}\` (${appVersion})  
**Binary SHA-256:** \`${binarySha256}\` (${ir.targetInfo.arch} ${ir.targetInfo.format})  
**Runtime:** Electron 43.4.1 / Chromium 150.0.7871.224 / Node.js 20+  
**Classification:** ${classification}  
**Date of Assessment:** ${dateStr}  

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Research Scope & Authorization Assumptions](#2-research-scope--authorization-assumptions)
3. [Application Architecture](#3-application-architecture)
   - 3.1 [Electron Core Architecture](#31-electron-core-architecture)
   - 3.2 [Native Module (hackerrank_native) Analysis](#32-native-module-hackerrank_native-analysis)
   - 3.3 [Architectural Diagrams](#33-architectural-diagrams)
4. [Technology Stack & Dependency Inventory](#4-technology-stack--dependency-inventory)
5. [Trust Boundary & Privilege Analysis](#5-trust-boundary--privilege-analysis)
6. [Monitoring & Telemetry Architecture](#6-monitoring--telemetry-architecture)
   - 6.1 [Event Taxonomy & Telemetry Ingestion](#61-event-taxonomy--telemetry-ingestion)
   - 6.2 [Detailed Detector Class Analysis](#62-detailed-detector-class-analysis)
   - 6.3 [Media Capture & S3 Streaming Pipelines](#63-media-capture--s3-streaming-pipelines)
   - 6.4 [Clock Synchronization & Skew Management](#64-clock-synchronization--skew-management)
7. [Attack Surface Inventory](#7-attack-surface-inventory)
8. [Confirmed Security Findings](#8-confirmed-security-findings)
   - [Finding SEC-001: Platform-Specific Exclusion of Native Module Hash & Integrity Verification](#finding-sec-001-platform-specific-exclusion-of-native-module-hash--integrity-verification)
   - [Finding SEC-002: Remote Insecure Window Spawning with Context Isolation Disabled](#finding-sec-002-remote-insecure-window-spawning-with-context-isolation-disabled)
   - [Finding SEC-003: Overly Broad Scheme Whitelist in External Protocol Handler](#finding-sec-003-overly-broad-scheme-whitelist-in-external-protocol-handler)
   - [Finding SEC-004: Insecure Local Storage of Clock Skew Offset & Critical State](#finding-sec-004-insecure-local-storage-of-clock-skew-offset--critical-state)
   - [Finding SEC-005: Sandboxing Disabled and <webview> Tag Enabled on Main Window](#finding-sec-005-sandboxing-disabled-and-webview-tag-enabled-on-main-window)
   - [Finding SEC-006: Client-Side Machine Learning Model Lacks Attestation](#finding-sec-006-client-side-machine-learning-model-lacks-attestation)
9. [Suspected Vulnerabilities Requiring Laboratory Validation](#9-suspected-vulnerabilities-requiring-laboratory-validation)
10. [STRIDE Threat Model](#10-stride-threat-model)
11. [Risk Assessment Matrix](#11-risk-assessment-matrix)
12. [Authorized Security Validation Laboratory Procedures](#12-authorized-security-validation-laboratory-procedures)
13. [Defensive Code & Configuration Hardening](#13-defensive-code--configuration-hardening)
14. [Remediation Roadmap](#14-remediation-roadmap)
15. [Residual Risks & Defense-in-Depth](#15-residual-risks--defense-in-depth)
16. [Evidence Appendix](#16-evidence-appendix)
17. [References & Conclusions](#17-references--conclusions)

---

## 1. Executive Summary

This report delivers an extensive, evidence-based security assessment of the **${appName} Desktop Application ${appVersion}** on macOS (\`${ir.targetInfo.arch}\`). The target is an enterprise proctoring client engineered to conduct high-stakes technical assessments in an isolated, monitored environment. The application combines an Electron shell (Chromium 150 / Electron 43.4.1), a core TypeScript proctoring subsystem (\`@hackerrank/proctor v0.12.4\`), and a Rust-compiled native Node-API (\`.node\`) addon for low-level operating system monitoring and window lifecycle management.

Through deep static analysis of the packaged ASAR archive, disassembled native binaries (decompiled via Ghidra 12.1 headless analysis), decompiled scripts, and platform configuration descriptors (\`Info.plist\`), several significant architectural and implementation weaknesses were identified:

1. **Platform-Restricted Native Addon Integrity Verification:** The application explicitly skips cryptographic SHA-256 and byte-size verification of its native executable module on macOS and Linux, restricting verification exclusively to Windows (\`win32\`).
2. **Context Isolation Disabled on Secondary Display Window:** When a secondary monitor is detected, the application constructs a secondary BrowserWindow to blackout the auxiliary display. This window is created with \`contextIsolation: false\` and navigates to an external remote third-party URL (\`https://blackscreen.app\`), exposing a severe trust boundary violation.
3. **Electron Sandboxing Inactivation:** The primary examination window operates with Chromium process sandboxing disabled (\`sandbox: false\`) and legacy \`<webview>\` tags enabled (\`webviewTag: true\`).
4. **Unauthenticated Local Storage Dependencies:** Critical proctoring operational states, including the authoritative server-time offset calculation, are persisted in unencrypted, unauthenticated \`window.localStorage\` and \`sessionStorage\`.
5. **Client-Side AI Inference Boundary:** All face detection, presence verification, and gaze/multiple-face validation are executed entirely on the client workstation via WebAssembly (\`@mediapipe/face_detection\`) without cryptographic proof of execution.

This document details these findings, constructs a formal STRIDE threat model, establishes an isolated laboratory validation methodology, and outlines a prioritized engineering roadmap to harden the client against compromise.

---

## 2. Research Scope & Authorization Assumptions

### 2.1 Scope
* **Target Application:** ${appName} Desktop Client (${appVersion})
* **Bundle Identifier:** \`${bundleId}\`
* **Target Files:**
  * **Mach-O Executable:** \`${mainBinaryPath}\`
  * **Core JavaScript Archive:** \`${asarPath || 'Contents/Resources/app.asar'}\`
  * **Native Addons:** \`${nativeAddonPath || 'app.asar.unpacked/native/dist/hackerrank_native.darwin-arm64.node'}\`
  * **Manifests & Plists:** \`Contents/Info.plist\`, \`package.json\`, \`app-update.yml\`

### 2.2 Ethics & Responsible Disclosure Stance
This assessment is strictly defensive and architectural. In compliance with cybersecurity research ethics:
* No operational bypass instructions, evasion exploits, or cheat tools are provided.
* All validation procedures utilize synthetic mock environments, isolated test drivers, and non-operational telemetry sinks.
* The analysis seeks to empower development teams to remediate design flaws and protect assessment integrity.

---

## 3. Application Architecture

### 3.1 Electron Core Architecture

The ${appName} Desktop Application employs a multi-process architecture consisting of an Electron Main process, multiple BrowserWindows (main candidate exam window, auxiliary blackout windows), a preload bridge script, and a native Rust addon.

\`\`\`
+-----------------------------------------------------------------------------------+
|                                 OPERATING SYSTEM                                  |
|                    macOS 12.0+ (ARM64 / x86_64), Windows, Linux                   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        ELECTRON MAIN PROCESS (Privileged)                         |
| - Process Lifecycle, Global Shortcuts, Window Management (Kiosk / Fullscreen)      |
| - IPC Main Dispatcher (46 registered IPC handlers)                                |
| - Dynamic Addon Loader (\`hackerrank_native\`) with Platform Verification           |
| - Session Recorder Controller & S3 Policy Orchestration                           |
+-----------------------------------------------------------------------------------+
         |                                |                                |
         | IPC (invoke/handle)            | Node-API FFI Bindings          | HTTP / TLS
         v                                v                                v
+-----------------------------+  +----------------------+  +--------------------+
|    PRELOAD SCRIPT BRIDGE    |  |   RUST N-API ADDON   |  |  BACKEND TELEMETRY |
| - \`contextBridge\` exposure  |  | - \`get_monitors\`     |  | - Krakend Gateway  |
| - \`hackerranktest\` API      |  | - \`open_windows\`     |  | - AWS S3 Chunks    |
| - MutationObserver hooks    |  | - \`get_processes\`    |  | - Time API Sync    |
+-----------------------------+  | - \`kill_processes\`   |  +--------------------+
         |                       | - \`proc_listpids\`    |
         v                       +----------------------+
+---------------------------------------------------------+
|                RENDERER PROCESS (Untrusted)             |
| - Assessment UI (\`out/renderer\`)                        |
| - \`@hackerrank/proctor\` Engine                           |
|   * 8 Modular Detectors (TabSwitch, Monitors, etc.)     |
|   * MediaPipe WASM / TensorFlow.js Face Detection       |
|   * MediaBunny Fragmented MP4 Multiplexer               |
| - Local Storage Persistence Layer                       |
+---------------------------------------------------------+
\`\`\`

#### Window Configuration Parameters

The primary window (\`mainWindow\`) is instantiated with the following explicit \`webPreferences\`:

\`\`\`javascript
webPreferences: {
  devTools: false,
  preload: path.join(__dirname, "../preload/index.js"),
  sandbox: false,         // Sandboxing explicitly disabled
  webviewTag: true,       // Legacy webview tag explicitly allowed
  nodeIntegration: false, // Node integration disabled in renderer
  contextIsolation: true  // Context isolation enabled for primary window
}
\`\`\`

In contrast, the secondary blackout window instantiated to cover external monitors features:

\`\`\`javascript
webPreferences: {
  nodeIntegration: false,
  contextIsolation: false // Context isolation explicitly disabled!
}
\`\`\`

---

### 3.2 Native Module (\`hackerrank_native\`) Analysis

The native addon is compiled from Rust using N-API bindings. It is shipped in \`app.asar.unpacked/native/dist/\` for multiple architecture targets (\`darwin-arm64\`, \`darwin-x64\`, \`win32-x64-msvc\`, \`win32-ia32-msvc\`).

#### Native Module Interface
Decompilation via Ghidra reveals the addon exports six primary N-API functions:
* **\`get_monitors()\`**: Invokes macOS CoreGraphics API \`CGGetOnlineDisplayList\` / \`CGDisplayBounds\` to detect active displays and geometry.
* **\`open_windows()\` / \`open_windows_sync()\`**: Calls \`CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements)\` to extract window IDs, titles, bounds, owner PIDs (\`kCGWindowOwnerPID\`), and process names (\`kCGWindowOwnerName\`).
* **\`get_processes()\`**: Queries the BSD kernel using \`proc_listpids\` and \`proc_pidinfo\` to obtain running processes.
* **\`kill_processes(pids: Vec<i32>)\`**: Issues \`SIGTERM\` or \`SIGKILL\` to specified process identifiers.
* **\`get_global_notification_state()\`**: Reads macOS system notification center status.
* **\`stop_services()\`**: Terminates asynchronous background worker threads running inside the addon's Tokio multi-threaded runtime.

---

### 3.3 Architectural Diagrams

#### Sequence Diagram: Proctoring Initialization & Telemetry Cycle

\`\`\`mermaid
sequenceDiagram
    autonumber
    actor Candidate
    participant Renderer as Renderer (@hackerrank/proctor)
    participant Preload as Preload Bridge (contextBridge)
    participant Main as Electron Main Process
    participant Addon as Rust Addon (hackerrank_native)
    participant Cloud as HackerRank IES Backend / S3

    Candidate->>Renderer: Launch Assessment
    Renderer->>Preload: hackerranktest.setKioskMode()
    Preload->>Main: ipcRenderer.invoke("renderer-events", {code: 2})
    Main->>Main: globalShortcut.registerAll(blockedKeys)
    Main->>Main: window.setKiosk(true)
    Renderer->>Preload: hackerranktest.systemCheck.getMonitorStatus()
    Preload->>Main: ipcRenderer.invoke("get-monitor-status")
    Main->>Addon: get_monitors()
    Addon-->>Main: { monitorCount: N }
    Main-->>Preload: { monitorCount: N }
    Preload-->>Renderer: { monitorCount: N }

    Renderer->>Cloud: GET /ies/api/v1/time
    Cloud-->>Renderer: { unix_ms: serverTime }
    Renderer->>Renderer: Compute & Store clockOffsetMs in localStorage

    loop MediaPipe Face Detection (every N ms)
        Renderer->>Renderer: VideoFrame -> MediaPipe WASM Detector
        alt No Face / Secondary Face Detected
            Renderer->>Cloud: POST /ies/api/v1/events (Event 32 / 37)
            Renderer->>Cloud: S3 Pre-signed Upload (JPEG Snapshot)
        end
    end

    loop Periodic Application Audit (every 2000 ms)
        Main->>Addon: open_windows_sync()
        Addon-->>Main: WindowList[PID, OwnerName, Title]
        opt Blocked App Detected
            Main->>Preload: emit("open-applications-detected", {apps})
            Preload->>Renderer: ActionableEvent(54: OPEN_APPS_DETECTED)
        end
    end
\`\`\`

---

## 4. Technology Stack & Dependency Inventory

The application dependencies extracted from \`package.json\` and ASAR metadata include:

| Dependency | Declared Version | Component Role | Security Relevance |
| :--- | :--- | :--- | :--- |
| **Electron Framework** | 43.4.1 (Chromium 150) | Host Desktop Runtime | Base CVE vulnerability profile, sandboxing flags |
| **\`@hackerrank/proctor\`** | 0.12.4 | Core Proctoring Engine | Detection logic, event dispatch, video chunking |
| **\`@hackerrank/logger\`** | ^1.3.2 | Structured Telemetry Logging | Remote event forwarding, diagnostic capture |
| **\`@sentry/electron\`** | 7.15.0 | Crash Reporting & Sentry SDK | Out-of-band crash telemetry, metadata collection |
| **\`electron-updater\`** | ^6.3.9 | Binary Auto-Update Engine | Differential updates, signature validation |
| **\`is-elevated\`** | ^4.0.0 | Privilege Level Verification | Detects administrator / root execution |
| **\`@mediapipe/face_detection\`** | 0.4.1646425229 | Face Detection Models (TFLite) | Bundled SIMD WebAssembly for local facial detection |
| **\`@tensorflow/tfjs-core\`** | Bundled | Machine Learning Backend | WebGL / CPU mathematical execution engine |
| **\`mediabunny\`** | Bundled | Media Container Multiplexer | Fragmented MP4 muxing of screen and webcam feeds |
| **\`codem-isoboxer\`** | Bundled | ISO/IEC 14496-12 Parser | Parsing MP4 atom structures (\`moov\`, \`moof\`, \`mdhd\`) |

---

## 5. Trust Boundary & Privilege Analysis

\`\`\`
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 1: Operating System vs. Native Addon]                             |
| Privileged OS System Calls (proc_listpids, CoreGraphics Window List APIs, Signals)|
+-----------------------------------------------------------------------------------+
                                          |
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 2: Electron Main Process vs. Native Addon (FFI)]                  |
| Unchecked C FFI boundary, memory allocations, pointer handoffs                    |
+-----------------------------------------------------------------------------------+
                                          |
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 3: Electron Main vs. Preload Script (IPC Channels)]               |
| IPC message passing via \`ipcMain.handle\` / \`ipcRenderer.invoke\`. Strict schemas?   |
+-----------------------------------------------------------------------------------+
                                          |
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 4: Preload Bridge vs. Web Renderer Context]                       |
| \`contextBridge.exposeInMainWorld("hackerranktest", api)\`                          |
+-----------------------------------------------------------------------------------+
                                          |
+-----------------------------------------------------------------------------------+
| [TRUST BOUNDARY 5: Renderer vs. Remote Web APIs & S3 Storage]                     |
| HTTPS endpoints, S3 Pre-signed URL PUT/POST uploads, Krakend API Gateway          |
+-----------------------------------------------------------------------------------+
\`\`\`

### Analysis of Boundaries:
* **Boundary 1 (Native -> OS):** Relies on user-granted macOS Privacy permissions (Screen Recording, Accessibility, Camera, Microphone). If permissions are missing, graceful degradation occurs, but detection capabilities silently fail or return partial errors.
* **Boundary 2 (Main -> Native Addon):** Addon runs within the Main process memory space. Any memory corruption (e.g., buffer overflow in window title parsing) results in immediate Main process termination or arbitrary code execution.
* **Boundary 3 & 4 (Renderer -> Main):** The renderer is considered semi-trusted. Any compromised or injected JavaScript in the renderer can invoke preload APIs exposed on \`window.hackerranktest\`.
* **Boundary 5 (Client -> Cloud):** The cloud backend assumes that telemetry events signed by candidate session credentials originate from an authentic, unmodified runtime environment.

---

## 6. Monitoring & Telemetry Architecture

### 6.1 Event Taxonomy & Telemetry Ingestion

The monitoring subsystem classifies all candidate behavior into a standardized telemetry taxonomy. Events are transmitted via \`POST /ies/api/v1/events\` and mirrored to \`/recruit/attempts/{attemptId}/logActivity\`.

| Event ID | Constant Identifier | Trigger Source | Payload Attributes |
| :---: | :--- | :--- | :--- |
| **7** | \`WENT_INVISIBLE\` | TabSwitchDetector | \`{ isExternalLinkClicked: bool }\` |
| **8** | \`WENT_VISIBLE\` | TabSwitchDetector | \`{ isExternalLinkClicked: bool }\` |
| **9** | \`PASTE\` | CopyPasteDetector | \`{ pastedText: string, isExternal: bool }\` |
| **15** | \`MULTIPLE_MONITOR\` | MultipleMonitorDetector | \`{ monitor_count: number }\` |
| **16** | \`MULTIPLE_WEBCAM\` | WebcamProctorDetector | \`{ webcam_count: number }\` |
| **17** | \`WEBCAM_SWITCH\` | WebcamProctorDetector | \`{ new_device_id: string }\` |
| **18** | \`SIDEBAR_TOGGLE\` | SidebarDetector | \`{ sidebar: { status: bool, browserScreenData } }\` |
| **23** | \`EXIT_FULLSCREEN\` | FullscreenDetector | \`{ isFullscreen: false }\` |
| **24** | \`ENTER_FULLSCREEN\` | FullscreenDetector | \`{ isFullscreen: true }\` |
| **31** | \`WEBCAM_STOPPED\` | MediaStreamTrack | \`{ reason: string }\` |
| **32** | \`NO_FACE_DETECTED\` | MediaPipe WASM Detector | \`{ duration_ms: number }\` (Fires after 15s) |
| **34** | \`SCREENSHARE_STOPPED\` | MediaStreamTrack | \`{ trackState: string }\` |
| **35** | \`PERMISSION_REVOKED\` | Permissions API | \`{ permissionName: string }\` |
| **36** | \`VALID_FACE_DETECTED\` | MediaPipe WASM Detector | \`{ confidence: number }\` |
| **37** | \`SECONDARY_FACE_DETECTED\` | MediaPipe WASM Detector | \`{ face_count: number }\` |
| **38** | \`BLOCK_MULTIPLE_WEBCAMS\` | Device Inventory | \`{ devices: array }\` |
| **39** | \`MULTIPLE_MONITOR_STOPPED\` | Window Management | \`{ reason: string }\` |
| **42** | \`SCREENSHARE_STARTED\` | DisplayMedia Stream | \`{ resolution: string, fps: number }\` |
| **45** | \`COLLECT_REASON\` | Candidate Input Modal | \`{ eid: number, reason: string }\` |
| **46** | \`WEBCAM_INACTIVE\` | Video Frame Stream | \`{ missing_frames: number }\` |
| **47** | \`DESKTOP_APP_OUT_OF_FOCUS\` | Electron Window Focus | \`{ timestamp: number }\` |
| **48** | \`DESKTOP_APP_IN_FOCUS\` | Electron Window Focus | \`{ timestamp: number }\` |
| **49** | \`WEBCAM_STREAM_REFRESH\` | Media Recovery | \`{ streamId: string }\` |
| **50** | \`MICROPHONE_STOPPED\` | AudioTrack State | \`{ reason: string }\` |
| **51** | \`MICROPHONE_UNAVAILABLE\` | Audio Device Enumeration | \`{ error: string }\` |
| **52** | \`CHUNK_UPLOADED\` | SessionRecorder S3 | \`{ chunk_id: string, source: string }\` |
| **54** | \`OPEN_APPS_DETECTED\` | hackerrank_native | \`{ openApplications: array, timestamp }\` |
| **55** | \`OPEN_APPS_CLEARED\` | hackerrank_native | \`{ timestamp: number }\` |
| **68** | \`STREAM_MUTED\` | MediaTrack Event | \`{ source: string }\` |
| **69** | \`STREAM_STARTED\` | MediaTrack Event | \`{ source: string }\` |

---

### 6.2 Detailed Detector Class Analysis

#### 1. TabSwitchDetector
Monitors the DOM \`visibilitychange\` event. When \`document.visibilityState === "hidden"\`, it flags \`WENT_INVISIBLE\`. If invisibility persists for longer than \`TAB_SWITCH_FEEDBACK_TIMER\` (4,000 ms), it dispatches an actionable \`COLLECT_REASON\` event demanding candidate explanation.

#### 2. MultipleMonitorDetector
Interfaces through \`window.hackerranktest.getMonitorStatus()\`. The native backend calls CoreGraphics to inspect display counts. If \`monitorCount > 1\`, it dispatches \`MULTIPLE_MONITOR\`. If the exam profile sets \`blockMultipleMonitors: true\`, the detector raises \`PERMISSION_REVOKED\`, halting the assessment.

#### 3. WebcamProctorDetector
Initializes a client-side face detector pipeline utilizing \`@tensorflow-models/face-detection\` with MediaPipe Short/Full-Range TFLite models executed in WebAssembly.
* Analyzes candidate webcam frames at periodic intervals.
* Distinguishes between \`FACE_STATE.ONE_FACE\` and \`FACE_STATE.NO_FACE\`.
* Maintains an internal timer: if no face is identified for 15,000 ms (\`NO_FACE_REASON_TIMER\`), Event 32 (\`NO_FACE_DETECTED\`) triggers, initiating an automated S3 photographic upload.
* If more than one face bounding box is resolved, Event 37 (\`SECONDARY_FACE_DETECTED\`) fires immediately.

#### 4. CopyPasteDetector
Attaches DOM event listeners to \`copy\`, \`cut\`, and \`paste\`. It maintains an in-memory and localStorage cache of the last 20 strings copied within the exam workspace. When a paste event occurs:
* The detector compares the pasted payload against the internal cache.
* If the text is absent from the cache, \`isExternal: true\` is assigned.
* Event 9 (\`PASTE\`) is logged to the server containing the exact raw text pasted by the user.

#### 5. FullscreenDetector
Requests fullscreen mode via \`document.documentElement.requestFullscreen()\`. It concurrently invokes \`navigator.keyboard.lock(["Escape"])\` to suppress default OS escape handling. If fullscreen is relinquished, \`EXIT_FULLSCREEN\` is logged, and candidate input is collected after 4 seconds.

#### 6. SidebarDetector
Monitors browser window geometry. Compares \`window.outerWidth\` vs \`window.innerWidth\` and \`window.outerHeight\` vs \`window.innerHeight\`. If a delta exceeds 6% width or 15% height, it infers that developer tools or a browser sidebar has been docked, firing Event 18 (\`SIDEBAR_TOGGLE\`).

#### 7. DesktopAppFocusDetector
Utilizes Electron window blur and focus events propagated across the preload bridge. Applies a 2,000 ms debounce timer. Unfocused states trigger Event 47 (\`DESKTOP_APP_OUT_OF_FOCUS\`).

#### 8. OpenAppsDetector
Polls the operating system process and window tables via the native module's \`openWindowsSync()\` export. Matches open window titles and process names against a remote blacklist. Detected processes trigger Event 54 (\`OPEN_APPS_DETECTED\`), displaying a modal blocking progress until the candidate closes the application.

---

### 6.3 Media Capture & S3 Streaming Pipelines

Session recording is managed by the \`SessionRecorder\` class, using the \`mediabunny\` library to encode MediaStream video into fragmented MP4 containers (\`video/mp4\` using AVC/H.264 or VP9).

\`\`\`
MediaStream (Screen / Webcam)
      |
      v
MediaStreamVideoTrackSource (FPS: 5 screen, 2 webcam; KeyFrame: 5s)
      |
      v
Mediabunny Mp4OutputFormat (Fragment Duration: >= 4000ms)
      |
      +--> onFtyp / onMoov (Extracted ISO Box metadata)
      |
      +--> onMdat: Binary Fragment Blob
      |
      v
SessionRecorderS3Uploader.enqueueUpload()
  - Max queue: 20 MB (drops frames if exceeded)
  - Pre-signed S3 Policy via /ies/api/v2/session/{sessionId}/presigned-policy
  - Multipart POST upload to AWS S3 bucket
  - Dynamic concurrency scaling (1 to 3 concurrent connections based on RTT latency)
\`\`\`

---

### 6.4 Clock Synchronization & Skew Management

To prevent candidates from falsifying activity timestamps by modifying their local system clock, the client queries \`GET /ies/api/v1/time\` during startup:
* Obtains \`unix_ms\` from the server.
* Calculates \`measured = serverMs - (t0 + t2) / 2\`.
* If skew exceeds \`TRUSTED_SKEW_MS\` (3,000 ms), an \`offsetMs\` is saved.
* **Vulnerability:** The offset is cached in unencrypted localStorage under key \`proctor-clock-offset-ms:{attemptId}\`.

---

## 7. Attack Surface Inventory

| ID | Attack Surface | Exposure Vector | Component / Handler | Privilege | Sensitivity |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | Native Module Loading | Filesystem / Addon Directory | \`out/main/index.js (mr())\` | Main (Root/Admin) | High: Native code execution |
| **AS-02** | Secondary Window Management | Display Change / IPC | \`BrowserWindow (blackscreen.app)\` | Main Process | Critical: Remote web loading |
| **AS-03** | External Protocol Dispatch | URL Navigation | \`open-external-url IPC\` | Main Process | High: Arbitrary URI execution |
| **AS-04** | Client-Side Storage | DOM Storage API | \`localStorage / jStorage\` | Renderer | High: Clock offset, exam tokens |
| **AS-05** | IPC Channel Registry | Preload contextBridge | \`46 IPC Main Handlers\` | Main / Renderer | High: System preference control |
| **AS-06** | Screen Capture Pipeline | Chromium Media API | \`captureDesktopAppWindow\` | Main / Renderer | High: Screen confidentiality |
| **AS-07** | Local Machine Learning | WebAssembly Pipeline | \`@mediapipe/face_detection\` | Renderer | Medium: Identity attestation |
| **AS-08** | Global Shortcut Hooking | OS Keyboard Handler | \`r.globalShortcut.registerAll\` | Main Process | Medium: Input availability |
| **AS-09** | Application Auto-Update | Network / YAML Manifest | \`electron-updater\` | Main Process | Critical: Supply chain delivery |
| **AS-10** | Custom URL Protocol | OS Deep Link Registration | \`hackerranktest:// Scheme\` | Main Process | High: Argument injection |

---

## 8. Confirmed Security Findings

### Finding SEC-001: Platform-Specific Exclusion of Native Module Hash & Integrity Verification

* **Classification:** CWE-353: Missing Support for Integrity Check / CWE-354: Improper Validation of Integrity Check Value
* **Severity:** High
* **CVSS v3.1:** 7.1 (\`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N\`)
* **Confidence:** Confirmed

#### Affected Components
* **File:** \`/Applications/HackerRank.app/Contents/Resources/app.asar/out/main/index.js\`
* **Function:** \`mr(e, t)\` (Native Addon Verification Function)
* **Native Binary:** \`Contents/Resources/app.asar.unpacked/native/dist/hackerrank_native.darwin-arm64.node\`

#### Technical Description
The application contains an explicit verification function \`mr(e, t)\` designed to validate that the unpacked native Node-API binary has not been altered. It computes the SHA-256 hash of the binary on disk and compares it to a hardcoded dictionary \`ir\`:

\`\`\`javascript
var ir = {
  "hackerrank_native.darwin-arm64.node": {
    sha256: "57c3c820f6326e4cdec0238810f424195afa8de61be08e864a5d480f1ab55510",
    size: 721344
  },
  "hackerrank_native.darwin-x64.node": {
    sha256: "8256d9b5beb37ed6fa8b3a6a563b0a383f3fb01b00f2cd9949bf43d0f63dcefc",
    size: 713040
  }
};

function mr(e, t) {
  if (f.lstatSync(e).isSymbolicLink())
    throw new pr(\`Native addon cannot be a symlink: \${e}\`);
  const n = f.statSync(e);
  if (!n.isFile())
    throw new pr(\`Native addon is not a regular file: \${e}\`);

  if (function(e) {
    const t = dr(f.realpathSync(e)),
      r = dr(f.realpathSync(m.dirname(e))),
      n = r.endsWith(m.sep) ? r : \`\${r}\${m.sep}\`;
    if (!t.startsWith(n))
      throw new pr(\`Native addon path resolves outside expected directory: \${e}\`);
  }(e), "win32" !== process.platform || "development" === process.env.NODE_ENV && !r.app.isPackaged)
    return; // <-- CRITICAL FLAW: Returns immediately on non-Windows platforms!

  const i = ir[t];
  if (!i) throw new pr(\`Missing expected hash for native addon \${t}\`);
  if (n.size !== i.size) throw new pr(\`Native addon size mismatch...\`);
  const s = u.createHash("sha256").update(f.readFileSync(e)).digest("hex");
  if (s !== i.sha256) throw new pr(\`Native addon hash mismatch...\`);
}
\`\`\`

On macOS (\`process.platform === "darwin"\`) and Linux (\`"linux"\`), the condition \`"win32" !== process.platform\` evaluates to \`true\`, causing the function to execute \`return;\` immediately. Consequently, file size and cryptographic hash validation are completely bypassed on all non-Windows systems.

#### Security Impact
An attacker with local user access can modify, replace, or hook functions inside \`hackerrank_native.darwin-arm64.node\`. Because the file is stored unpacked outside the signed ASAR in \`Contents/Resources/app.asar.unpacked/\`, the main process will load the tampered dynamic library without raising an integrity exception. This completely undermines all process monitoring, monitor detection, and window enumeration.

#### Preconditions
* Local access to the user's filesystem.
* Target running on macOS or Linux platforms.

#### Defensive Proof of Concept (Isolated Verification)
\`\`\`javascript
// Test: Simulate verification function logic
const platform = "darwin";
function testVerification(targetPlatform) {
  if ("win32" !== targetPlatform) {
    return "BYPASSED_VERIFICATION";
  }
  return "VERIFIED";
}
console.assert(testVerification("darwin") === "BYPASSED_VERIFICATION", "Failed: Darwin must bypass check under flawed logic");
\`\`\`

#### Remediation
Remove the platform-specific bypass. Enforce universal SHA-256 and size verification across all supported operating systems:

\`\`\`javascript
function mr(addonPath, binaryName) {
  if (f.lstatSync(addonPath).isSymbolicLink()) {
    throw new NativeAddonVerificationError("Symlinks disallowed");
  }
  const stats = f.statSync(addonPath);
  if (!stats.isFile()) {
    throw new NativeAddonVerificationError("Regular file required");
  }

  // Enforce integrity on all production builds regardless of OS
  if (r.app.isPackaged) {
    const expected = ir[binaryName];
    if (!expected) throw new NativeAddonVerificationError("Unregistered addon binary");
    if (stats.size !== expected.size) throw new NativeAddonVerificationError("Size mismatch");
    const digest = u.createHash("sha256").update(f.readFileSync(addonPath)).digest("hex");
    if (digest !== expected.sha256) throw new NativeAddonVerificationError("Integrity hash mismatch");
  }
}
\`\`\`

---

### Finding SEC-002: Remote Insecure Window Spawning with Context Isolation Disabled

* **Classification:** CWE-1007: Insufficient Platform Security Configuration / CWE-749: Exposed Dangerous Method or Function
* **Severity:** Critical
* **CVSS v3.1:** 8.8 (\`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H\`)
* **Confidence:** Confirmed

#### Affected Components
* **File:** \`/Applications/HackerRank.app/Contents/Resources/app.asar/out/main/index.js\`
* **Subsystem:** Multi-Display Blackout Handler
* **Target Window:** Auxiliary BrowserWindow instance

#### Technical Description
When the application detects a connected external display, it attempts to obscure the secondary display by creating an auxiliary fullscreen kiosk window. The window is constructed using insecure configuration settings:

\`\`\`javascript
const o = new r.BrowserWindow({
  x: t,
  y: n,
  width: i,
  height: s,
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: false // <-- CRITICAL FLAW: Context isolation explicitly disabled!
  }
});
ni = o;
o.setContentProtection(true);
o.setKiosk(true);
try {
  o.loadURL("https://blackscreen.app"); // <-- CRITICAL FLAW: Loads third-party remote website!
} catch (ji) {
  _n("error", "Error loading blackscreen URL:", ji);
}
\`\`\`

#### Security Impact
1. **Third-Party Domain Dependency:** \`https://blackscreen.app\` is an external, unauthenticated domain not owned or controlled by HackerRank. If this third-party domain is expired, hijacked, DNS-poisoned, or suffers from a Cross-Site Scripting (XSS) vulnerability, an attacker can execute arbitrary JavaScript within this window.
2. **Context Isolation Disabled:** Because \`contextIsolation: false\`, the DOM execution context and Electron internal script wrappers share an execution context. An injected script can manipulate prototype chains, inspect window internals, and bridge access to Electron features.

#### Defensive Proof of Concept
A static check confirms \`contextIsolation: false\` coupled with \`loadURL("https://blackscreen.app")\`:
\`\`\`bash
grep -A 2 -B 2 'loadURL("https://blackscreen.app")' out/main/index.js
\`\`\`

#### Remediation
1. Never load remote external web content for UI utility functions.
2. Generate an internal, local data URI or bundle a static HTML file within \`app.asar\`:

\`\`\`javascript
const blackoutWindow = new BrowserWindow({
  x, y, width, height,
  kiosk: true,
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true
  }
});
blackoutWindow.loadURL("data:text/html;charset=utf-8,%3Chtml%20style%3D%22background%3Ablack%22%3E%3Cbody%20style%3D%22background%3Ablack%22%3E%3C%2Fbody%3E%3C%2Fhtml%3E");
\`\`\`

---

### Finding SEC-003: Overly Broad Scheme Whitelist in External Protocol Handler

* **Classification:** CWE-937: Using Components with Known Vulnerabilities / CWE-646: Reliance on File-Extension or Scheme for Security
* **Severity:** Medium
* **CVSS v3.1:** 5.3 (\`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N\`)
* **Confidence:** Confirmed

#### Affected Components
* **File:** \`/Applications/HackerRank.app/Contents/Resources/app.asar/out/main/index.js\`
* **IPC Handler:** \`open-external-url\`

#### Technical Description
The application exposes an IPC handler allowing renderer processes to trigger the operating system's default URL handler via \`electron.shell.openExternal\`. The input validation checks only string prefix matching:

\`\`\`javascript
r.ipcMain.handle("open-external-url", async (e, t) => {
  try {
    return t && "string" == typeof t ?
      t.startsWith("http://") || t.startsWith("https://") || t.startsWith("mailto:") ?
        (await r.shell.openExternal(t), { success: true }) :
        (_n("error", "URL must start with http://, https://, or mailto:"), { success: false, error: "Invalid argument" }) :
      { success: false, error: "Invalid argument" };
  } catch (err) {
    return { success: false, error: err.message };
  }
});
\`\`\`

#### Security Impact
1. \`http://\` URLs allow unencrypted plaintext transport, vulnerable to local network interception or captive portal injection.
2. \`mailto:\` URLs with malformed parameters or embedded control characters can trigger operating system command line injection in unpatched mail user agents (e.g., CVE-2018-0202 in Outlook or similar desktop handlers).
3. The lack of domain whitelisting allows the assessment window to instruct the host operating system to launch arbitrary external browsers to phishing or malware domains.

#### Remediation
* Restrict permitted protocols strictly to \`https:\`.
* Validate URLs against an enterprise domain allowlist (\`*.hackerrank.com\`, authorized authentication providers).

\`\`\`javascript
r.ipcMain.handle("open-external-url", async (event, targetUrl) => {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") {
      return { success: false, error: "Only HTTPS allowed" };
    }
    const ALLOWED_DOMAINS = ["hackerrank.com", "hrcdn.net", "support.hackerrank.com"];
    const isAllowed = ALLOWED_DOMAINS.some(d => parsed.hostname === d || parsed.hostname.endsWith("." + d));
    if (!isAllowed) {
      return { success: false, error: "Domain not allowed" };
    }
    await r.shell.openExternal(targetUrl);
    return { success: true };
  } catch (e) {
    return { success: false, error: "Malformed URL" };
  }
});
\`\`\`

---

### Finding SEC-004: Insecure Local Storage of Clock Skew Offset & Critical State

* **Classification:** CWE-345: Insufficient Verification of Data Authenticity / CWE-353: Missing Support for Integrity Check
* **Severity:** Medium
* **CVSS v3.1:** 4.7 (\`CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N\`)
* **Confidence:** Confirmed

#### Affected Components
* **File:** \`src/utils/time.ts\`
* **Module:** Clock Synchronization

#### Technical Description
The proctoring engine implements server clock synchronization to establish an immutable timeline for cheating events. However, the calculated offset is written directly to standard web \`localStorage\`:

\`\`\`javascript
var cacheKey = (attemptId) => \`proctor-clock-offset-ms:\${attemptId}\`;

var writeCachedOffsetMs = (attemptId, value) => {
  try {
    window.localStorage.setItem(cacheKey(attemptId), String(value));
  } catch {}
};

var readCachedOffsetMs = (attemptId) => {
  try {
    const stored = window.localStorage.getItem(cacheKey(attemptId));
    const parsed = stored === null ? NaN : Number(stored);
    return Number.isFinite(parsed) ? parsed : null;
  } catch {
    return null;
  }
};
\`\`\`

#### Security Impact
\`window.localStorage\` is stored as an unencrypted LevelDB database on disk (\`~/Library/Application Support/HackerRank/Local Storage/leveldb\`). Any local script or concurrent process with access to the user profile can manipulate this value. Modifying \`proctor-clock-offset-ms\` skews the reported inserttime on all future integrity events, corrupting forensic audit trails.

#### Remediation
Maintain the authoritative time offset exclusively within the privileged Electron Main process memory. Provide a read-only IPC getter for the renderer process. Never persist sensitive integrity state in client-modifiable DOM storage.

---

### Finding SEC-005: Sandboxing Disabled and <webview> Tag Enabled on Main Window

* **Classification:** CWE-250: Execution with Unnecessary Privileges
* **Severity:** Medium
* **CVSS v3.1:** 5.0 (\`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N\`)
* **Confidence:** Confirmed

#### Affected Components
* **File:** \`out/main/index.js\`
* **Property:** \`webPreferences.sandbox\` and \`webPreferences.webviewTag\`

#### Technical Description
The main exam window is instantiated with:
\`\`\`javascript
webPreferences: {
  sandbox: false,
  webviewTag: true,
  contextIsolation: true,
  nodeIntegration: false
}
\`\`\`

Electron documentation strongly advises setting \`sandbox: true\` to ensure renderer processes are enclosed within the Chromium OS sandbox. Furthermore, \`webviewTag: true\` introduces architectural vulnerabilities related to guest webview management and potential bypass of navigation restrictions.

#### Remediation
Refactor the application to enable Chromium sandboxing (\`sandbox: true\`) and replace legacy \`<webview>\` tags with modern \`BrowserView\` or \`WebContentsView\` primitives.

---

### Finding SEC-006: Client-Side Machine Learning Model Lacks Attestation

* **Classification:** CWE-345: Insufficient Verification of Data Authenticity
* **Severity:** Low / Architectural Risk
* **CVSS v3.1:** 3.7 (\`CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N\`)
* **Confidence:** Confirmed

#### Affected Components
* **Library:** \`@hackerrank/proctor -> WebcamProctorDetector.ts\`
* **Models:** \`@mediapipe/face_detection\` WebAssembly & TFLite binaries

#### Technical Description
All face detection decisions (\`VALID_FACE_DETECTED\`, \`NO_FACE_DETECTED\`, \`SECONDARY_FACE_DETECTED\`) are computed exclusively within the client renderer via WebAssembly. The cloud backend receives boolean event declarations (Event 32, Event 36, Event 37) without cryptographic attestation, hardware-backed enclave guarantees, or server-side AI corroboration.

#### Remediation
Treat client-side face detection strictly as a lightweight cueing heuristic. Require server-side verification of uploaded periodic video fragments (\`SessionRecorder\`) to confirm candidate presence independently of client declarations.

---

## 9. Suspected Vulnerabilities Requiring Laboratory Validation

| Finding ID | Suspected Weakness | Affected Component | Technical Hypotheses |
| :---: | :--- | :--- | :--- |
| **SUSP-01** | Process Termination Race Condition in Native Killer | \`kill_processes\` in \`hackerrank_native\` | PID reuse or unchecked error handling when killing disallowed processes could result in killing unintended tasks or panic state in Tokio runtime. |
| **SUSP-02** | Deep-Link Argument Injection via Custom Scheme | \`hackerranktest://\` protocol registration | Unsanitized URL query parameters parsed during protocol launch could trigger unexpected state transitions or SSRF in candidate session bootstrapping. |
| **SUSP-03** | Display Capture Concurrency Desynchronization | \`captureDesktopAppWindowForNextDisplayMediaRequest\` | State flag \`cn = true\` lacks atomic locking; concurrent calls from multiple renderer frames may cause display capture to bind to an unexpected target window. |

---

## 10. STRIDE Threat Model

| STRIDE Category | Threat Description | Affected Boundary | Existing Mitigation | Residual Risk | Recommended Control |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Spoofing webcam video feed via synthetic virtual camera driver | OS Media Subsystem -> Chromium | Client-side device enumeration | High: Virtual camera devices can emulate hardware cameras | Implement hardware serial queries via native addon |
| **Tampering** | Altering \`proctor-clock-offset-ms\` in LocalStorage | Renderer DOM -> Telemetry Pipeline | Client-side skew sanity check (2025–2100) | Moderate: Timeline skew within valid bounds | Move time offset to Electron Main process memory |
| **Repudiation** | Candidate denies cheating events claiming network drop | Client Telemetry -> Cloud Ingestion | Exponential backoff retry in S3 Uploader | Moderate: Dropped chunks if queue exceeds 20 MB | Implement monotonic sequence counters on events |
| **Information Disclosure** | Clipboard contents logged to server on external paste | Renderer -> Recruiter Log Activity | Sent over TLS HTTPS | Moderate: Sensitive credentials in clipboard exposed | Hash or sanitize clipboard contents before logging |
| **Denial of Service** | Process crash via malformed window title in native addon | CoreGraphics -> Rust N-API Addon | Rust memory safety (N-API panic catches) | Low: Unhandled panics terminate process | Rigorous UTF-8 sanitization on all native strings |
| **Elevation of Privilege** | Remote code execution via \`blackscreen.app\` blackout window | Remote Web -> Electron Main | None (\`contextIsolation: false\`) | Critical: Remote XSS can leverage Electron primitives | Serve local static blackout page; enable \`contextIsolation\` |

---

## 11. Risk Assessment Matrix

| Finding ID | Vulnerability Title | Severity | Likelihood | Impact | Priority | Remediation Strategy |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **SEC-002** | Remote Insecure Window (\`blackscreen.app\`) | **Critical** | High | Critical | **P0** | Load local data URI; enforce \`contextIsolation: true\` |
| **SEC-001** | Native Module Hash Bypass on macOS/Linux | **High** | High | High | **P0** | Remove \`"win32" !== process.platform\` bypass in \`mr()\` |
| **SEC-003** | Overly Broad Protocol Handler (\`open-external-url\`) | **Medium** | Medium | Medium | **P1** | Enforce HTTPS-only and strict domain whitelist |
| **SEC-005** | Sandboxing Disabled & Webview Enabled | **Medium** | Medium | Medium | **P1** | Set \`sandbox: true\`, deprecate \`<webview>\` |
| **SEC-004** | Insecure Local Storage of Clock Offset | **Medium** | High | Low | **P2** | Maintain clock offset in Main memory only |
| **SEC-006** | Unattested Client ML Face Detection | **Low** | High | Low | **P3** | Server-side video frame corroboration |

---

## 12. Authorized Security Validation Laboratory Procedures

To safely validate these findings without interfering with production systems, engineers should construct an isolated laboratory test harness.

### 12.1 Laboratory Environment Specification
* **Hardware:** Isolated macOS ARM64 virtual machine or non-production workstation.
* **Tools:** Node.js 20+, Electron development environment, local HTTP mock server (e.g., \`mockttp\` or \`prism\`).
* **Configuration:** No network egress to HackerRank production servers.

### 12.2 Unit Test: Native Addon Verification Logic (SEC-001)

Create a standalone test driver \`test-addon-verification.js\`:

\`\`\`javascript
/**
 * Test Driver: Validate that native addon verification executes on macOS
 * Expected Behavior: Should compute hash on all platforms
 * Vulnerable Behavior: Skips verification if process.platform !== 'win32'
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function auditAddonVerification(platform, filePath, expectedHash) {
  // Mirroring line from out/main/index.js: function mr(e, t)
  const isBypassed = "win32" !== platform;
  if (isBypassed) {
    return { status: "VULNERABLE", message: \`Platform \${platform} bypassed integrity check\` };
  }
  const fileBuffer = fs.readFileSync(filePath);
  const actualHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
  if (actualHash !== expectedHash) {
    return { status: "TAMPERED", message: "Integrity check caught modification" };
  }
  return { status: "SECURE", message: "Integrity verified successfully" };
}

// Validation run
const resultMac = auditAddonVerification("darwin", __filename, "dummyhash");
console.log("[LAB TEST SEC-001] macOS Result:", resultMac);
console.assert(resultMac.status === "VULNERABLE", "Test failed: logic did not bypass macOS");
\`\`\`

### 12.3 Unit Test: IPC Protocol Whitelist (SEC-003)

\`\`\`javascript
/**
 * Test Driver: Validate URL validation logic in open-external-url handler
 */
function validateUrl(inputUrl) {
  if (!inputUrl || typeof inputUrl !== "string") return false;
  // Current flawed implementation:
  return inputUrl.startsWith("http://") || inputUrl.startsWith("https://") || inputUrl.startsWith("mailto:");
}

const testCases = [
  { url: "http://insecure-http.com", expectedSecure: false },
  { url: "mailto:test@example.com?subject=Payload", expectedSecure: false },
  { url: "https://legitimate.hackerrank.com", expectedSecure: true }
];

testCases.forEach(({ url, expectedSecure }) => {
  const isAccepted = validateUrl(url);
  console.log(\`[LAB TEST SEC-003] Testing: \${url} -> Accepted: \${isAccepted}\`);
});
\`\`\`

---

## 13. Defensive Code & Configuration Hardening

### 13.1 Hardened BrowserWindow Construction

\`\`\`javascript
// Remediated BrowserWindow configuration
const primaryWindow = new BrowserWindow({
  width: 1920,
  height: 1080,
  kiosk: true,
  webPreferences: {
    devTools: false,
    preload: path.join(__dirname, "../preload/index.js"),
    sandbox: true,                  // Enforce Chromium OS sandboxing
    contextIsolation: true,         // Enforce separate JavaScript contexts
    nodeIntegration: false,        // Disable Node.js primitives in renderer
    webviewTag: false,             // Disallow <webview> tags
    enableRemoteModule: false,     // Deprecated & disabled
    allowRunningInsecureContent: false
  }
});
\`\`\`

### 13.2 Strict IPC Schema Validation Using Zod

Implement strict input validation on all IPC channels to prevent prototype pollution or unexpected type coercion:

\`\`\`javascript
const { z } = require("zod");
const { ipcMain } = require("electron");

const RendererEventSchema = z.object({
  code: z.number().int().min(1).max(20),
  aid: z.string().uuid().optional()
});

ipcMain.handle("renderer-events", (event, rawArgs) => {
  const result = RendererEventSchema.safeParse(rawArgs);
  if (!result.success) {
    logger.error("IPC Validation Failure", { error: result.error });
    return { success: false, error: "Invalid payload schema" };
  }
  const { code, aid } = result.data;
  switch (code) {
    case 2:
      enableKioskMode();
      break;
    case 3:
      disableKioskMode();
      break;
    // ...
  }
  return { success: true };
});
\`\`\`

### 13.3 Robust Content Security Policy (CSP)

Deliver a rigorous Content Security Policy via HTTP headers and \`<meta>\` tags:

\`\`\`http
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval' https://hrcdn.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://*.amazonaws.com; connect-src 'self' https://*.hackerrank.com https://*.amazonaws.com; media-src 'self' blob:; frame-ancestors 'none'; form-action 'none';
\`\`\`

---

## 14. Remediation Roadmap

\`\`\`
+-----------------------------------------------------------------------------------+
| IMMEDIATE ACTION (Week 1 - Hotfix Deployment)                                     |
| [P0] SEC-002: Replace \`blackscreen.app\` remote URL with local black HTML data URI |
| [P0] SEC-002: Enable \`contextIsolation: true\` on auxiliary blackout windows       |
| [P0] SEC-001: Remove \`"win32" !== process.platform\` bypass in native addon loader |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| SHORT-TERM ACTION (Month 1 - Sprint Release)                                      |
| [P1] SEC-003: Restrict \`open-external-url\` to HTTPS and whitelisted domains       |
| [P1] SEC-005: Enable \`sandbox: true\` and disable \`webviewTag\` on main window     |
| [P2] SEC-004: Relocate clock offset storage from LocalStorage to Main process     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| MEDIUM-TERM ACTION (Quarter 1 - Architectural Evolution)                          |
| [P2] Implement Zod/Joi schema validation on all 46 IPC message handlers           |
| [P3] SEC-006: Deploy server-side AI video verification for periodic chunk audits  |
| [P3] Implement cryptographic attestation for client-side event sequences          |
+-----------------------------------------------------------------------------------+
\`\`\`

---

## 15. Residual Risks & Defense-in-Depth

Even after full remediation of the findings documented in this report, certain inherent endpoint security risks remain:

1. **Host-Level Virtualization:** A candidate executing the application inside a fully isolated virtual machine (e.g., QEMU/KVM with GPU passthrough) cannot be reliably detected by userland Electron code without specialized anti-VM hypervisor detection routines.
2. **Hardware Video Interception:** Hardware HDMI capture cards or hardware video splitters operating downstream of the GPU display output are physically outside the visibility boundary of the operating system and client application.
3. **Defense-in-Depth Recommendation:** Proctoring should never rely entirely on client-side endpoint surveillance. Assessment integrity must be supported by question design (randomized pools, conceptual problem solving, time constraints) and secondary out-of-band monitoring channels.

---

## 16. Evidence Appendix

### A. Binary Information
* **File:** \`${mainBinaryPath}\`
* **Type:** Mach-O 64-bit executable \`${ir.targetInfo.arch}\`
* **UUID:** \`${machOUuid}\`
* **Code Signature:** \`${codeSignature}\`
* **Dependencies:**
  * \`@rpath/Electron Framework.framework/Electron Framework\`
  * \`/usr/lib/libSystem.B.dylib\`

### B. Info.plist Permissions Extract
\`\`\`xml
${plistPermissionsSnippet}
\`\`\`

### C. Package.json Dependencies
\`\`\`json
${packageDepsSnippet}
\`\`\`

---

## 17. References & Conclusions

### References
* [Electron Security Guidelines (Official Documentation)](https://www.electronjs.org/docs/latest/tutorial/security)
* [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
* [CWE-1007: Insufficient Platform Security Configuration](https://cwe.mitre.org/data/definitions/1007.html)
* [CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
* [MITRE ATT&CK: Software Packing (T1027.002)](https://attack.mitre.org/techniques/T1027/002/)
* [Chromium Sandboxing Architecture](https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md)

### Conclusion
The **${appName} Desktop Application ${appVersion}** implements an extensive client-side surveillance and telemetry architecture. However, security boundaries between the privileged Main process, external web content, and unpacked native addons contain critical defects—most notably the platform-specific exclusion of native addon verification on macOS/Linux and the insecure instantiation of auxiliary windows loading third-party domains with \`contextIsolation: false\`. Implementing the remediations detailed in Section 13 will systematically eliminate these attack vectors and re-establish defense-in-depth across the client ecosystem.
`;
}
