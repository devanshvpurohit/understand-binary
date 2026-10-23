#!/usr/bin/env node
import { Command } from 'commander';
import * as path from 'node:path';
import * as fs from 'node:fs';
import pc from 'picocolors';
import { analyzeBinaryTarget } from '@understand-binary/core-re';
import { normalizeBinaryAnalysis } from '@understand-binary/bridge';
import { synthesizeKnowledgeGraph } from '@understand-binary/graph-engine';
import { startDashboardServer } from './server.js';

const program = new Command();

program
  .name('ub')
  .description('Understand-Binary: Reverse engineer applications and visualize their technical architecture.')
  .version('0.1.0');

program
  .command('analyze <target>')
  .description('Analyze a binary executable, package, or application bundle')
  .option('-o, --output <dir>', 'Output directory for knowledge graph', '.ub')
  .option('--dashboard', 'Immediately launch interactive visualization dashboard after analysis', false)
  .option('-p, --port <port>', 'Dashboard port', '3000')
  .action(async (target: string, options) => {
    try {
      const targetPath = path.resolve(process.cwd(), target);
      if (!fs.existsSync(targetPath)) {
        console.error(pc.red(`Error: Target file not found at ${targetPath}`));
        process.exit(1);
      }

      console.log(pc.cyan(`\n🔍 [Understand-Binary] Ingesting and reversing target:`));
      console.log(`   ${pc.bold(targetPath)}\n`);

      const startTime = Date.now();

      // Phase 1: REA Ingestion & Decompilation
      console.log(pc.blue(`[1/3] Running REA extraction & symbol disassembly...`));
      const reResult = await analyzeBinaryTarget(targetPath);
      console.log(
        pc.gray(
          `      Format: ${pc.green(reResult.metadata.format.toUpperCase())} | Functions: ${pc.white(
            reResult.functions.length.toString()
          )} | Strings: ${pc.white(reResult.strings.length.toString())}`
        )
      );

      // Phase 2: Bridge & Architectural Normalization
      console.log(pc.blue(`[2/3] Normalizing symbols and inferring subsystems...`));
      const archIR = normalizeBinaryAnalysis(reResult);
      console.log(
        pc.gray(
          `      Subsystems: ${pc.magenta(archIR.subsystems.length.toString())} | Components: ${pc.white(
            archIR.components.length.toString()
          )} | Relationships: ${pc.white(archIR.relationships.length.toString())}`
        )
      );

      // Phase 3: Understand-Anything Knowledge Graph Synthesis
      console.log(pc.blue(`[3/3] Synthesizing Understand-Anything knowledge graph...`));
      const knowledgeGraph = synthesizeKnowledgeGraph(archIR);

      // Save Output
      const outDir = path.resolve(process.cwd(), options.output);
      if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }

      const graphFile = path.join(outDir, 'knowledge-graph.json');
      const irFile = path.join(outDir, 'architecture-ir.json');
      fs.writeFileSync(graphFile, JSON.stringify(knowledgeGraph, null, 2), 'utf-8');
      fs.writeFileSync(irFile, JSON.stringify(archIR, null, 2), 'utf-8');

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(pc.green(`\n✓ Analysis complete in ${elapsed}s!`));
      console.log(`  Graph generated: ${pc.cyan(graphFile)}`);
      console.log(`  Nodes: ${pc.bold(knowledgeGraph.nodes.length.toString())} | Edges: ${pc.bold(knowledgeGraph.edges.length.toString())}`);

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

program.parse(process.argv);
