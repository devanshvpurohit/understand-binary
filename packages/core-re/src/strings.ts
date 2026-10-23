import * as fs from 'node:fs';
import type { ExtractedString } from './types.js';

const URL_REGEX = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]{4,120}/g;
const FILEPATH_REGEX = /(?:\/[\w.-]+){2,}\/?|(?:[a-zA-Z]:\\[\w.-]+(?:\\[\w.-]+)+)/g;
const SQL_REGEX = /\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|DROP TABLE)\b\s+[^;]{4,100}/gi;
const KEY_TOKEN_REGEX = /\b(?:api[_-]?key|secret|token|bearer|auth[_-]?header|private[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9_\-.]{12,64})/gi;

export function extractStringsFromBuffer(buffer: Buffer, maxStrings = 500): ExtractedString[] {
  const text = buffer.toString('utf-8');
  const results: ExtractedString[] = [];
  const seen = new Set<string>();

  const add = (val: string, classification: ExtractedString['classification']) => {
    const trimmed = val.trim();
    if (trimmed.length < 5 || trimmed.length > 256 || seen.has(trimmed)) return;
    seen.add(trimmed);
    results.push({
      value: trimmed,
      classification,
    });
  };

  // Find URLs
  let match: RegExpExecArray | null;
  while ((match = URL_REGEX.exec(text)) !== null && results.length < maxStrings) {
    add(match[0], 'url');
  }

  // Find Filepaths
  while ((match = FILEPATH_REGEX.exec(text)) !== null && results.length < maxStrings) {
    add(match[0], 'filepath');
  }

  // Find SQL
  while ((match = SQL_REGEX.exec(text)) !== null && results.length < maxStrings) {
    add(match[0], 'sql');
  }

  // Find Potential Keys
  while ((match = KEY_TOKEN_REGEX.exec(text)) !== null && results.length < maxStrings) {
    add(match[0], 'key_or_token');
  }

  // Extract general printable ASCII sequences >= 7 chars if under limit
  if (results.length < maxStrings) {
    const printableRegex = /[\x20-\x7E]{7,60}/g;
    while ((match = printableRegex.exec(text)) !== null && results.length < maxStrings) {
      const candidate = match[0];
      if (!candidate.startsWith('   ') && !/^[\s.,\/#!$%\^&\*;:{}=\-_`~()]+$/.test(candidate)) {
        add(candidate, 'general');
      }
    }
  }

  return results;
}

export function extractStringsFromFile(filePath: string, maxStrings = 500): ExtractedString[] {
  if (!fs.existsSync(filePath)) return [];
  const buffer = fs.readFileSync(filePath);
  return extractStringsFromBuffer(buffer, maxStrings);
}
