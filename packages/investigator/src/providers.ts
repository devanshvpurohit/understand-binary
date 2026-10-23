export interface ProviderMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ProviderOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface LLMProvider {
  name: string;
  generateText(messages: ProviderMessage[], options?: ProviderOptions): Promise<string>;
}

export class GeminiProvider implements LLMProvider {
  name = 'gemini';
  private apiKey: string;
  private model: string;

  constructor(apiKey?: string, model = 'gemini-1.5-flash') {
    this.apiKey = apiKey || process.env.GEMINI_API_KEY || '';
    this.model = model;
  }

  async generateText(messages: ProviderMessage[]): Promise<string> {
    if (!this.apiKey) throw new Error('GEMINI_API_KEY not configured.');
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
    const prompt = messages.map((m) => `${m.role.toUpperCase()}: ${m.content}`).join('\n\n');

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
      }),
    });

    if (!res.ok) {
      throw new Error(`Gemini API error: ${res.status} ${await res.text()}`);
    }
    const data: any = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated.';
  }
}

export class ClaudeProvider implements LLMProvider {
  name = 'claude';
  private apiKey: string;
  private model: string;

  constructor(apiKey?: string, model = 'claude-3-5-sonnet-20241022') {
    this.apiKey = apiKey || process.env.ANTHROPIC_API_KEY || '';
    this.model = model;
  }

  async generateText(messages: ProviderMessage[]): Promise<string> {
    if (!this.apiKey) throw new Error('ANTHROPIC_API_KEY not configured.');
    const system = messages.find((m) => m.role === 'system')?.content || '';
    const userMessages = messages.filter((m) => m.role !== 'system');

    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 2048,
        system,
        messages: userMessages.map((m) => ({ role: m.role, content: m.content })),
      }),
    });

    if (!res.ok) {
      throw new Error(`Claude API error: ${res.status} ${await res.text()}`);
    }
    const data: any = await res.json();
    return data.content?.[0]?.text || 'No response generated.';
  }
}

export class OpenAIProvider implements LLMProvider {
  name = 'openai';
  private apiKey: string;
  private model: string;

  constructor(apiKey?: string, model = 'gpt-4o-mini') {
    this.apiKey = apiKey || process.env.OPENAI_API_KEY || '';
    this.model = model;
  }

  async generateText(messages: ProviderMessage[]): Promise<string> {
    if (!this.apiKey) throw new Error('OPENAI_API_KEY not configured.');
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages,
      }),
    });

    if (!res.ok) {
      throw new Error(`OpenAI API error: ${res.status} ${await res.text()}`);
    }
    const data: any = await res.json();
    return data.choices?.[0]?.message?.content || 'No response generated.';
  }
}

export class OllamaProvider implements LLMProvider {
  name = 'ollama';
  private baseUrl: string;
  private model: string;

  constructor(baseUrl?: string, model = 'llama3.2') {
    this.baseUrl = baseUrl || process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.model = model;
  }

  async generateText(messages: ProviderMessage[]): Promise<string> {
    const res = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages,
        stream: false,
      }),
    });

    if (!res.ok) {
      throw new Error(`Ollama API error: ${res.status} ${await res.text()}`);
    }
    const data: any = await res.json();
    return data.message?.content || 'No response generated.';
  }
}

export function resolveLLMProvider(): LLMProvider | null {
  if (process.env.GEMINI_API_KEY) return new GeminiProvider();
  if (process.env.ANTHROPIC_API_KEY) return new ClaudeProvider();
  if (process.env.OPENAI_API_KEY) return new OpenAIProvider();
  if (process.env.OLLAMA_ENABLED === 'true') return new OllamaProvider();
  return null;
}
