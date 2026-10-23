import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { ArchitectureIR } from '@understand-binary/bridge';
import { BinaryInspectionTools } from './tools.js';

export function createMCPServer(ir: ArchitectureIR): Server {
  const tools = new BinaryInspectionTools(ir);

  const server = new Server(
    {
      name: 'understand-binary',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'get_analysis_status',
          description: 'Get overall binary analysis status, architecture metadata, and analysis coverage.',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'list_functions',
          description: 'List functions/symbols discovered in the binary with role filtering.',
          inputSchema: {
            type: 'object',
            properties: {
              limit: { type: 'number', description: 'Max items to return (default 50)' },
              offset: { type: 'number', description: 'Pagination offset' },
              role: { type: 'string', description: 'Filter by role (e.g. cryptography, network, storage, ui, auth)' },
            },
          },
        },
        {
          name: 'get_function',
          description: 'Get comprehensive details for a function by name or address.',
          inputSchema: {
            type: 'object',
            properties: {
              addressOrName: { type: 'string', description: 'Function address or symbol name' },
            },
            required: ['addressOrName'],
          },
        },
        {
          name: 'get_disassembly',
          description: 'Get instructions, opcodes, and assembly disassembly for a function.',
          inputSchema: {
            type: 'object',
            properties: {
              addressOrName: { type: 'string', description: 'Function address or symbol name' },
            },
            required: ['addressOrName'],
          },
        },
        {
          name: 'get_callers',
          description: 'Retrieve verified callers and xrefs pointing to a function.',
          inputSchema: {
            type: 'object',
            properties: {
              addressOrName: { type: 'string', description: 'Function address or symbol name' },
            },
            required: ['addressOrName'],
          },
        },
        {
          name: 'get_callees',
          description: 'Retrieve verified functions called by a specified function.',
          inputSchema: {
            type: 'object',
            properties: {
              addressOrName: { type: 'string', description: 'Function address or symbol name' },
            },
            required: ['addressOrName'],
          },
        },
        {
          name: 'search_strings',
          description: 'Search extracted string literals (URLs, file paths, SQL, tokens).',
          inputSchema: {
            type: 'object',
            properties: {
              pattern: { type: 'string', description: 'Substring to search for' },
              classification: { type: 'string', description: 'Filter: url, filepath, key_or_token, sql' },
            },
          },
        },
        {
          name: 'search_symbols',
          description: 'Search symbol table by name or address.',
          inputSchema: {
            type: 'object',
            properties: {
              pattern: { type: 'string', description: 'Symbol pattern to match' },
            },
            required: ['pattern'],
          },
        },
        {
          name: 'find_call_path',
          description: 'Find a static call execution path between two functions on the call graph.',
          inputSchema: {
            type: 'object',
            properties: {
              source: { type: 'string', description: 'Source function name or address' },
              target: { type: 'string', description: 'Target function name or address' },
            },
            required: ['source', 'target'],
          },
        },
        {
          name: 'get_security_findings',
          description: 'Get automated security findings (unsafe memory APIs, hardcoded keys, cleartext HTTP).',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    let result: any;
    switch (name) {
      case 'get_analysis_status':
        result = tools.getAnalysisStatus();
        break;
      case 'list_functions':
        result = tools.listFunctions(args.limit as any, args.offset as any, args.role as any);
        break;
      case 'get_function':
        result = tools.getFunction(args.addressOrName as string);
        break;
      case 'get_disassembly':
        result = tools.getDisassembly(args.addressOrName as string);
        break;
      case 'get_callers':
        result = tools.getCallers(args.addressOrName as string);
        break;
      case 'get_callees':
        result = tools.getCallees(args.addressOrName as string);
        break;
      case 'search_strings':
        result = tools.searchStrings(args.pattern as any, args.classification as any);
        break;
      case 'search_symbols':
        result = tools.searchSymbols(args.pattern as string);
        break;
      case 'find_call_path':
        result = tools.findCallPath(args.source as string, args.target as string);
        break;
      case 'get_security_findings':
        result = tools.getSecurityFindings();
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  });

  return server;
}

export async function runMCPServerStdio(ir: ArchitectureIR): Promise<void> {
  const server = createMCPServer(ir);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
