import { Detection } from './index';

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

export async function detectEnvVarLeak(toolUseData: any): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Check for sensitive environment variables
  for (const pattern of SENSITIVE_ENV_VAR_PATTERNS) {
    if (pattern.test(toolInput)) {
      // Extra check: is it in a dangerous context?
      const hasDangerousContext = DANGEROUS_COMMAND_CONTEXTS.some(ctx => ctx.test(toolInput));

      if (hasDangerousContext) {
        return {
          severity: 'high',
          message: 'Environment variable containing sensitive data detected in command output or network request',
          detector: 'env-var-leak'
        };
      } else {
        // Still flag it, but lower severity if not in obviously dangerous context
        return {
          severity: 'medium',
          message: 'Environment variable containing potential secrets detected in command',
          detector: 'env-var-leak'
        };
      }
    }
  }

  return null;
}
