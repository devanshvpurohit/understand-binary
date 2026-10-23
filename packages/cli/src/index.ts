#!/usr/bin/env node
import { Command } from 'commander';
import * as path from 'node:path';
import * as fs from 'node:fs';
import pc from 'picocolors';
import { analyzeBinaryTarget } from '@understand-binary/core-re';
import { normalizeBinaryAnalysis } from '@understand-binary/bridge';
import { synthesizeKnowledgeGraph } from '@understand-binary/graph-engine';
import { scanSecurityFindings, runMCPServerStdio, BinaryInvestigator } from '@understand-binary/investigator';
import { startDashboardServer } from './server.js';

const program = new Command();

program
  .name('ub')
  .description('Understand-Binary: Production-grade binary reverse engineering platform and architecture visualizer.')
  .version('0.1.0');

program
  .command('analyze <target>')
  .description('Analyze a binary executable, package, or application bundle')
  .option('-o, --output <dir>', 'Output directory for analysis artifacts', '.ub')
  .option('--dashboard', 'Immediately launch interactive visualization dashboard after analysis', false)
  .option('-p, --port <port>', 'Dashboard port', '3000')
  .option('-f, --force', 'Force full re-analysis even if cached artifacts exist', false)
  .action(async (target: string, options) => {
    try {
      const targetPath = path.resolve(process.cwd(), target);
      if (!fs.existsSync(targetPath)) {
        console.error(pc.red(`Error: Target file not found at ${targetPath}`));
        process.exit(1);
      }

      console.log(pc.cyan(`\n🔍 [Understand-Binary] Ingesting and analyzing target:`));
      console.log(`   ${pc.bold(targetPath)}\n`);

      const outDir = path.resolve(process.cwd(), options.output);
      const cacheDir = path.join(outDir, 'cache');
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }

      const startTime = Date.now();

      // Compute safe SHA-256 for file or directory bundle
      let sha256 = '';
      const stat = fs.statSync(targetPath);
      if (stat.isDirectory()) {
        const macosDir = path.join(targetPath, 'Contents', 'MacOS');
        if (fs.existsSync(macosDir)) {
          const files = fs.readdirSync(macosDir);
          if (files.length > 0 && fs.existsSync(path.join(macosDir, files[0]))) {
            const mainBin = path.join(macosDir, files[0]);
            if (!fs.statSync(mainBin).isDirectory()) {
              sha256 = (await import('node:crypto')).createHash('sha256').update(fs.readFileSync(mainBin)).digest('hex');
            }
          }
        }
        if (!sha256) {
          sha256 = (await import('node:crypto')).createHash('sha256').update(targetPath).digest('hex');
        }
      } else {
        const fileBuffer = fs.readFileSync(targetPath);
        sha256 = (await import('node:crypto')).createHash('sha256').update(fileBuffer).digest('hex');
      }
      const cacheFile = path.join(cacheDir, `${sha256}.json`);

      let knowledgeGraph: any;
      let archIR: any;
      let securityFindings: any;

      if (!options.force && fs.existsSync(cacheFile)) {
        console.log(pc.green(`✓ Loading cached analysis results (${pc.dim(sha256.substring(0, 16))}...)`));
        const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
        knowledgeGraph = cached.knowledgeGraph;
        archIR = cached.archIR;
        securityFindings = cached.securityFindings;
      } else {
        // Phase 1: REA Ingestion, Disassembly, & Symbol Extraction
        console.log(pc.blue(`[1/4] Running extraction, disassembly & instruction decoding...`));
        const reResult = await analyzeBinaryTarget(targetPath);
        console.log(
          pc.gray(
            `      Format: ${pc.green(reResult.metadata.format.toUpperCase())} (${reResult.metadata.architecture}) | Functions: ${pc.white(
              reResult.functions.length.toString()
            )} | Strings: ${pc.white(reResult.strings.length.toString())}`
          )
        );

        // Phase 2: Bridge & Architectural Normalization
        console.log(pc.blue(`[2/4] Normalizing symbols, instruction xrefs and inferring subsystems...`));
        archIR = normalizeBinaryAnalysis(reResult);
        console.log(
          pc.gray(
            `      Subsystems: ${pc.magenta(archIR.subsystems.length.toString())} | Components: ${pc.white(
              archIR.components.length.toString()
            )} | Relationships: ${pc.white(archIR.relationships.length.toString())}`
          )
        );

        // Phase 3: Static Security Findings Scanner
        console.log(pc.blue(`[3/4] Scanning for security findings and unsafe primitives...`));
        securityFindings = scanSecurityFindings(archIR);
        console.log(
          pc.gray(
            `      Security Findings: ${securityFindings.length > 0 ? pc.yellow(securityFindings.length.toString()) : pc.green('0')}`
          )
        );

        // Phase 4: Understand-Anything Knowledge Graph Synthesis
        console.log(pc.blue(`[4/4] Synthesizing Understand-Anything knowledge graph...`));
        knowledgeGraph = synthesizeKnowledgeGraph(archIR);

        // Save Cache
        fs.writeFileSync(
          cacheFile,
          JSON.stringify({ knowledgeGraph, archIR, securityFindings }, null, 2),
          'utf-8'
        );
      }

      // Persist Artifacts
      const graphFile = path.join(outDir, 'knowledge-graph.json');
      const irFile = path.join(outDir, 'architecture-ir.json');
      const findingsFile = path.join(outDir, 'security-findings.json');

      fs.writeFileSync(graphFile, JSON.stringify(knowledgeGraph, null, 2), 'utf-8');
      fs.writeFileSync(irFile, JSON.stringify(archIR, null, 2), 'utf-8');
      fs.writeFileSync(findingsFile, JSON.stringify(securityFindings, null, 2), 'utf-8');

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(pc.green(`\n✓ Analysis complete in ${elapsed}s!`));
      console.log(`  Artifacts saved to: ${pc.cyan(outDir)}`);
      console.log(`  Nodes: ${pc.bold(knowledgeGraph.nodes.length.toString())} | Edges: ${pc.bold(knowledgeGraph.edges.length.toString())} | Findings: ${pc.bold(securityFindings.length.toString())}`);

      if (options.dashboard) {
        console.log(pc.cyan(`\n🚀 Launching visual architecture explorer...`));
        const url = await startDashboardServer(outDir, parseInt(options.port, 10));
        console.log(`  Dashboard running at: ${pc.bold(pc.underline(url))}`);
      } else {
        console.log(pc.gray(`\nTo explore the architecture interactively, run:`));
        console.log(pc.white(`  ub serve ${options.output}\n`));
      }
    } catch (err: any) {
      console.error(pc.red(`\n❌ Analysis failed: ${err.message}`));
      process.exit(1);
    }
  });

program
  .command('serve [dir]')
  .description('Launch the interactive architecture visualizer for a generated graph')
  .option('-p, --port <port>', 'Dashboard port', '3000')
  .action(async (dir = '.ub', options) => {
    try {
      const graphDir = path.resolve(process.cwd(), dir);
      const url = await startDashboardServer(graphDir, parseInt(options.port, 10));
      console.log(pc.cyan(`\n✨ Understand-Binary Dashboard is live:`));
      console.log(`   ${pc.bold(pc.underline(url))}\n`);
    } catch (err: any) {
      console.error(pc.red(`\n❌ Failed to launch dashboard: ${err.message}`));
      process.exit(1);
    }
  });

program
  .command('mcp [dir]')
  .description('Launch the Model Context Protocol (MCP) stdio server for AI agents')
  .action(async (dir = '.ub') => {
    try {
      const irPath = path.resolve(process.cwd(), dir, 'architecture-ir.json');
      if (!fs.existsSync(irPath)) {
        console.error(pc.red(`Error: Analysis artifacts not found at ${irPath}. Run 'ub analyze <binary>' first.`));
        process.exit(1);
      }
      const ir = JSON.parse(fs.readFileSync(irPath, 'utf-8'));
      await runMCPServerStdio(ir);
    } catch (err: any) {
      console.error(pc.red(`MCP Server failed: ${err.message}`));
      process.exit(1);
    }
  });

program
  .command('investigate <question>')
  .description('Run an evidence-first AI investigation on an analyzed binary')
  .option('-d, --dir <dir>', 'Directory containing analysis artifacts', '.ub')
  .action(async (question: string, options) => {
    try {
      const irPath = path.resolve(process.cwd(), options.dir, 'architecture-ir.json');
      if (!fs.existsSync(irPath)) {
        console.error(pc.red(`Error: Analysis artifacts not found at ${irPath}. Run 'ub analyze <binary>' first.`));
        process.exit(1);
      }
      const ir = JSON.parse(fs.readFileSync(irPath, 'utf-8'));
      const investigator = new BinaryInvestigator(ir);

      console.log(pc.cyan(`\n🕵️ [Understand-Binary] Investigating Question:`));
      console.log(`   "${pc.bold(question)}"\n`);

      const result = await investigator.investigate(question);

      console.log(pc.green(`Summary:`));
      console.log(`  ${result.summary}\n`);

      if (result.provenFacts.length > 0) {
        console.log(pc.blue(`Verified Facts (${result.provenFacts.length}):`));
        for (const fact of result.provenFacts) {
          console.log(`  ✓ ${fact}`);
        }
        console.log();
      }

      if (result.evidenceCitations.length > 0) {
        console.log(pc.magenta(`Evidence Citations:`));
        for (const c of result.evidenceCitations) {
          console.log(`  • [${pc.cyan(c.addressOrSymbol)}]: ${c.description}`);
        }
        console.log();
      }

      console.log(pc.gray(`Tools Executed: ${result.toolCallsExecuted.join(', ')}\n`));
    } catch (err: any) {
      console.error(pc.red(`Investigation failed: ${err.message}`));
      process.exit(1);
    }
  });

program.parse(process.argv);
