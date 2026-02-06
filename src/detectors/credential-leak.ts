import type { Detection, ToolUseData } from '../types';
import type { CredentialLeakConfig } from '../config/types';

// Service-specific credential patterns (high confidence - always alert)
const SERVICE_SPECIFIC_PATTERNS = [
  // GitHub tokens
  /ghp_[a-zA-Z0-9]{36}/,
  /gho_[a-zA-Z0-9]{36}/,
  /ghu_[a-zA-Z0-9]{36}/,
  /ghs_[a-zA-Z0-9]{36}/,
  /ghr_[a-zA-Z0-9]{36}/,
  /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,

  // AWS credentials
  /(?:^|[^a-zA-Z0-9])(?:AWS|AKIA)[A-Z0-9]{16,}/,

  // Stripe keys
  /(?:^|[^a-zA-Z0-9])sk_live_[a-zA-Z0-9]{24,}/,
  /(?:^|[^a-zA-Z0-9])sk_test_[a-zA-Z0-9]{24,}/,
  /(?:^|[^a-zA-Z0-9])pk_live_[a-zA-Z0-9]{24,}/,
  /(?:^|[^a-zA-Z0-9])rk_live_[a-zA-Z0-9]{24,}/,

  // OpenAI / Anthropic style
  /(?:^|[^a-zA-Z0-9])sk-[a-zA-Z0-9]{48}/,
  /(?:^|[^a-zA-Z0-9])sk-ant-[a-zA-Z0-9-]{95,}/,

  // Slack tokens
  /xox[baprs]-[a-zA-Z0-9-]{10,}/,

  // Twilio
  /AC[a-z0-9]{32}/,
  /SK[a-z0-9]{32}/,

  // SendGrid
  /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,

  // Discord
  /(?:^|[^a-zA-Z0-9])[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27}/,
  /(?:^|[^a-zA-Z0-9])Bot [a-zA-Z0-9_-]{59}/,

  // SSH private key headers
  /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,

  // Google API keys
  /AIza[0-9A-Za-z_-]{35}/,

  // npm tokens
  /npm_[a-zA-Z0-9]{36}/,

  // PyPI tokens
  /pypi-[a-zA-Z0-9_-]{90,}/,
];

// Generic credential patterns (require context/entropy checking)
const GENERIC_CREDENTIAL_PATTERNS = [
  // Generic key/secret/password patterns
  {
    pattern:
      /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/i,
    captureGroup: 1,
  },
  {
    pattern: /(?:api[_-]?key|secret|token|password)[=:]\s*['"]?([A-Za-z0-9+/]{32,}={0,2})['"]?/i,
    captureGroup: 1,
  },
];

// Common placeholder/example patterns to ignore
const PLACEHOLDER_PATTERNS = [
  /(?:example|placeholder|dummy|fake|test|your|my|sample)[_-]?(key|token|secret|password)/i,
  /(?:key|token|secret|password)[_-]?(?:example|placeholder|dummy|fake|test|here|goes|value)/i,
  /^xxx+$/i, // Only xxx repeated
  /^yyy+$/i, // Only yyy repeated
  /^zzz+$/i, // Only zzz repeated
  /^(123)+$/, // Only 123 repeated
  /^(abc)+$/i, // Only abc repeated
  /^0+$/, // Only zeros
  /replace[_-]?(?:this|me|with)/i,
  /\*\*\*+|\.\.\.|<<<|>>>/,
];

/**
 * Calculate Shannon entropy to detect random-looking strings
 * High entropy = more random = more likely to be a real credential
 */
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const freq of Object.values(frequencies)) {
    const p = freq / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a string looks like a placeholder or example
 */
function isPlaceholder(str: string): boolean {
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(str)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a potential credential has sufficient entropy
 * Real credentials should have high randomness
 */
function hasSufficientEntropy(value: string, minEntropy = 3.0): boolean {
  if (value.length < 8) return false;
  return calculateEntropy(value) >= minEntropy;
}

export function detectCredentialLeak(
  toolUseData: ToolUseData,
  config?: CredentialLeakConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const minEntropy = config?.minEntropy ?? 3.0;
  const ignorePlaceholders = config?.ignorePlaceholders ?? true;
  const severity = config?.severity ?? 'high';
  const customPatterns = config?.customPatterns ?? [];

  const toolInput = JSON.stringify(toolUseData);

  // Check custom patterns first if provided
  for (const patternStr of customPatterns) {
    try {
      const pattern = new RegExp(patternStr);
      if (pattern.test(toolInput)) {
        return Promise.resolve({
          severity,
          message: 'Custom credential pattern detected',
          detector: 'credential-leak',
        });
      }
    } catch {
      // Invalid regex pattern, skip it
      console.warn(`Invalid custom pattern: ${patternStr}`);
    }
  }

  // Check service-specific patterns first (high confidence, no false positive checks needed)
  for (const pattern of SERVICE_SPECIFIC_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message: 'Service-specific credential detected (GitHub, AWS, Stripe, Slack, etc.)',
        detector: 'credential-leak',
      });
    }
  }

  // Check generic patterns with entropy/placeholder filtering
  for (const { pattern, captureGroup } of GENERIC_CREDENTIAL_PATTERNS) {
    const match = pattern.exec(toolInput);
    const credentialValue = match?.[captureGroup];
    if (credentialValue) {
      // Skip if it looks like a placeholder (if enabled)
      if (ignorePlaceholders && isPlaceholder(credentialValue)) {
        continue;
      }

      // Require sufficient entropy for generic patterns
      if (!hasSufficientEntropy(credentialValue, minEntropy)) {
        continue;
      }

      return Promise.resolve({
        severity,
        message: 'Potential credential or API key detected in command',
        detector: 'credential-leak',
      });
    }
  }

  return Promise.resolve(null);
}
