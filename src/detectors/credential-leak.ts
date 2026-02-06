import type { Detection, ToolUseData } from '../types';

const CREDENTIAL_PATTERNS = [
  /(?:^|[^a-zA-Z0-9])(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/i,
  /(?:^|[^a-zA-Z0-9])(?:AWS|AKIA)[A-Z0-9]{16,}/,
  /ghp_[a-zA-Z0-9]{36}/,
  /gho_[a-zA-Z0-9]{36}/,
  /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
  /(?:^|[^a-zA-Z0-9])sk-[a-zA-Z0-9]{48}/,
];

export function detectCredentialLeak(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message: 'Potential credential or API key detected in command',
        detector: 'credential-leak',
      });
    }
  }

  return Promise.resolve(null);
}
