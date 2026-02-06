import type { Detection, ToolUseData } from '../types';

/**
 * Detects environment variables containing secrets being exposed in commands
 */

const SENSITIVE_ENV_VAR_PATTERNS = [
  // AWS credentials
  /\$(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/,

  // GCP credentials
  /\$(?:GCP_PROJECT|GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_PROJECT)\b/,

  // Azure credentials
  /\$(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID)\b/,

  // Generic secrets
  /\$(?:API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN)\b/,
  /\$(?:[A-Z_]*SECRET[A-Z_]*|[A-Z_]*PASSWORD[A-Z_]*|[A-Z_]*TOKEN[A-Z_]*|[A-Z_]*KEY[A-Z_]*)\b/,

  // Database credentials
  /\$(?:DATABASE_URL|DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGODB_URI)\b/,

  // Service-specific
  /\$(?:GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD)\b/,
  /\$(?:SLACK_TOKEN|SLACK_WEBHOOK|DISCORD_TOKEN)\b/,
  /\$(?:STRIPE_SECRET_KEY|STRIPE_API_KEY)\b/,
  /\$(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY)\b/,

  // SSH keys
  /\$(?:SSH_PRIVATE_KEY|SSH_KEY)\b/,

  // JWT secrets
  /\$(?:JWT_SECRET|JWT_PRIVATE_KEY)\b/,

  // Export statements with secrets
  /\bexport\s+(?:[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)[A-Z_]*)\s*=/,
];

const DANGEROUS_COMMAND_CONTEXTS = [
  // Echo/print (exposes to stdout)
  /\b(?:echo|printf|print)\b[^\n]*\$/,

  // Logging to files
  /\$[A-Z_]+[^\n]*>>/,

  // Network requests with env vars
  /\b(?:curl|wget|http|fetch)\b[^\n]*\$/,

  // Git commits with env vars
  /\bgit\s+commit\b[^\n]*\$/,
];

// Indirect environment variable exposure patterns
const INDIRECT_DUMP_PATTERNS = [
  // Dump all environment variables
  /\b(?:env|printenv|export)\s*(?:\||$)/,

  // Grep for secrets in env
  /\b(?:env|printenv|export|set)\s+\|\s*grep\s+(?:-[^\n]+\s+)?(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)/i,

  // Display environment via set
  /\bset\s*(?:\||$)/,

  // Cat .env files
  /\bcat\s+[^\n]*\.env(?:\.[^\s]*)?/,

  // Less/more .env files
  /\b(?:less|more|head|tail)\s+[^\n]*\.env/,

  // Copy .env files
  /\bcp\s+[^\n]*\.env/,

  // Print env to files
  /\b(?:env|printenv)\s*>[^>]/,
];

// Safe contexts where env vars are just being checked, not exposed
const SAFE_CONTEXTS = [
  // Variable assignments (not exposure) - one var assigned to another
  /^[A-Z_]+="\$[A-Z_]+"$/,
];

/**
 * Check if the command is in a safe context
 */
function isSafeContext(command: string): boolean {
  for (const pattern of SAFE_CONTEXTS) {
    if (pattern.test(command)) {
      return true;
    }
  }
  return false;
}

export function detectEnvVarLeak(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Check for indirect dumps first (high priority)
  for (const pattern of INDIRECT_DUMP_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Command dumps environment variables to output - may expose multiple secrets at once',
        detector: 'env-var-leak',
      });
    }
  }

  // Skip if in safe context
  if (isSafeContext(toolInput)) {
    return Promise.resolve(null);
  }

  // Check for sensitive environment variables
  for (const pattern of SENSITIVE_ENV_VAR_PATTERNS) {
    if (pattern.test(toolInput)) {
      // Extra check: is it in a dangerous context?
      const hasDangerousContext = DANGEROUS_COMMAND_CONTEXTS.some((ctx) => ctx.test(toolInput));

      if (hasDangerousContext) {
        return Promise.resolve({
          severity: 'high',
          message:
            'Environment variable containing sensitive data detected in command output or network request',
          detector: 'env-var-leak',
        });
      } else {
        // Still flag it, but lower severity if not in obviously dangerous context
        return Promise.resolve({
          severity: 'medium',
          message: 'Environment variable containing potential secrets detected in command',
          detector: 'env-var-leak',
        });
      }
    }
  }

  return Promise.resolve(null);
}
