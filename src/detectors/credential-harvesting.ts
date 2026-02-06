import type { Detection, ToolUseData } from '../types';
import type { CredentialHarvestingConfig } from '../config/types';

/**
 * Detects attempts to steal or harvest stored credentials from the system
 */

// SSH credential patterns
const SSH_CREDENTIAL_PATTERNS = [
  // Reading SSH private keys
  /\bcat\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bcat\s+~?\/\.ssh\/[^\s]*key\b/,
  /\bless\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bmore\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bhead\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\btail\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,

  // Copying/exfiltrating SSH keys
  /\bcp\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bmv\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bscp\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\btar\s+[^\n]*~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)/,
  /\bzip\s+[^\n]*~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)/,

  // Encoding SSH keys (for exfiltration)
  /\bbase64\s+~?\/\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)\b/,
  /\bcat\s+~?\/\.ssh\/id_[^\n]*\|\s*base64/,

  // Reading entire .ssh directory
  /\bcat\s+~?\/\.ssh\/\*/,
  /\btar\s+[^\n]*~?\/\.ssh\b/,
  /\bzip\s+[^\n]*~?\/\.ssh\b/,
];

// AWS credential patterns
const AWS_CREDENTIAL_PATTERNS = [
  // Reading AWS credentials
  /\bcat\s+~?\/\.aws\/credentials\b/,
  /\bcat\s+~?\/\.aws\/config\b/,
  /\bless\s+~?\/\.aws\/credentials\b/,
  /\bmore\s+~?\/\.aws\/credentials\b/,
  /\bhead\s+~?\/\.aws\/credentials\b/,
  /\btail\s+~?\/\.aws\/credentials\b/,

  // Copying AWS credentials
  /\bcp\s+~?\/\.aws\/credentials\b/,
  /\bscp\s+~?\/\.aws\/credentials\b/,
  /\btar\s+[^\n]*~?\/\.aws\b/,
  /\bzip\s+[^\n]*~?\/\.aws\b/,

  // Encoding AWS credentials
  /\bbase64\s+~?\/\.aws\/credentials\b/,
  /\bcat\s+~?\/\.aws\/credentials[^\n]*\|\s*base64/,
];

// Browser credential patterns
const BROWSER_CREDENTIAL_PATTERNS = [
  // Chrome password database
  /\bcat\s+.*(?:Chrome|chromium).*Login.*Data/i,
  /\bcp\s+.*(?:Chrome|chromium).*Login.*Data/i,
  /\bsqlite3\s+.*(?:Chrome|chromium).*Login.*Data/i,

  // Firefox password database
  /\bcat\s+.*firefox.*logins\.json/i,
  /\bcat\s+.*firefox.*key[34]\.db/i,
  /\bcp\s+.*firefox.*logins\.json/i,
  /\bcp\s+.*firefox.*key[34]\.db/i,
  /\bsqlite3\s+.*firefox.*signons\.sqlite/i,

  // Generic browser credential access
  /\bfind\s+.*(?:-name|Chrome|Firefox|chromium|mozilla).*(?:Login|logins|password|key)/i,
  /\blocate\s+.*(?:Chrome|Firefox).*(?:Login|logins|password|Data)/i,
];

// Docker credential patterns
const DOCKER_CREDENTIAL_PATTERNS = [
  // Reading Docker config
  /\bcat\s+~?\/\.docker\/config\.json\b/,
  /\bless\s+~?\/\.docker\/config\.json\b/,
  /\bmore\s+~?\/\.docker\/config\.json\b/,
  /\bjq\s+[^\n]*~?\/\.docker\/config\.json/,

  // Copying Docker credentials
  /\bcp\s+~?\/\.docker\/config\.json\b/,
  /\bscp\s+~?\/\.docker\/config\.json\b/,

  // Encoding Docker credentials
  /\bbase64\s+~?\/\.docker\/config\.json\b/,
  /\bcat\s+~?\/\.docker\/config\.json[^\n]*\|\s*base64/,
];

// Kubernetes credential patterns
const KUBERNETES_CREDENTIAL_PATTERNS = [
  // Reading kubeconfig
  /\bcat\s+~?\/\.kube\/config\b/,
  /\bless\s+~?\/\.kube\/config\b/,
  /\bmore\s+~?\/\.kube\/config\b/,
  /\bhead\s+~?\/\.kube\/config\b/,
  /\btail\s+~?\/\.kube\/config\b/,

  // Copying kubeconfig
  /\bcp\s+~?\/\.kube\/config\b/,
  /\bscp\s+~?\/\.kube\/config\b/,
  /\btar\s+[^\n]*~?\/\.kube\b/,
  /\bzip\s+[^\n]*~?\/\.kube\b/,

  // Encoding kubeconfig
  /\bbase64\s+~?\/\.kube\/config\b/,
  /\bcat\s+~?\/\.kube\/config[^\n]*\|\s*base64/,

  // kubectl config view (can expose tokens)
  /\bkubectl\s+config\s+view\b/,
];

// Git credential patterns
const GIT_CREDENTIAL_PATTERNS = [
  // Reading git credentials
  /\bcat\s+~?\/\.git-credentials\b/,
  /\bcat\s+~?\/\.gitconfig\b/,
  /\bless\s+~?\/\.git-credentials\b/,
  /\bmore\s+~?\/\.git-credentials\b/,

  // Git credential helper extraction
  /\bgit\s+config\s+--get\s+credential\.helper\b/,
  /\bgit\s+credential\s+fill\b/,
  /\bgit\s+credential-cache\s+exit\b/,

  // Copying git credentials
  /\bcp\s+~?\/\.git-credentials\b/,
  /\bscp\s+~?\/\.git-credentials\b/,

  // Encoding git credentials
  /\bbase64\s+~?\/\.git-credentials\b/,
  /\bcat\s+~?\/\.git-credentials[^\n]*\|\s*base64/,
];

// Shell history patterns (may contain passwords)
const SHELL_HISTORY_PATTERNS = [
  // Reading shell history
  /\bcat\s+~?\/\.bash_history\b/,
  /\bcat\s+~?\/\.zsh_history\b/,
  /\bcat\s+~?\/\.history\b/,
  /\bcat\s+~?\/\.sh_history\b/,
  /\bless\s+~?\/\.bash_history\b/,
  /\bless\s+~?\/\.zsh_history\b/,
  /\bmore\s+~?\/\.bash_history\b/,
  /\bgrep\s+[^\n]*~?\/\.bash_history\b/,
  /\bgrep\s+[^\n]*~?\/\.zsh_history\b/,

  // Copying shell history
  /\bcp\s+~?\/\.bash_history\b/,
  /\bcp\s+~?\/\.zsh_history\b/,
  /\bscp\s+~?\/\.bash_history\b/,
  /\bscp\s+~?\/\.zsh_history\b/,

  // Encoding shell history
  /\bbase64\s+~?\/\.bash_history\b/,
  /\bcat\s+~?\/\.bash_history[^\n]*\|\s*base64/,
];

// Process memory patterns
const PROCESS_MEMORY_PATTERNS = [
  // Reading /proc/[pid]/environ (contains credentials)
  /\bcat\s+\/proc\/[0-9]+\/environ/,
  /\bcat\s+\/proc\/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/environ/,
  /\bstrings\s+\/proc\/[0-9]+\/environ/,

  // Reading /proc/[pid]/cmdline (may contain credentials)
  /\bcat\s+\/proc\/[0-9]+\/cmdline/,
  /\bcat\s+\/proc\/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/cmdline/,

  // Bulk process scraping
  /\bfor\s+[^\n]*\/proc\/[^\n]*\/environ/,
  /\bfind\s+\/proc[^\n]*-name\s+environ/,
  /\bfind\s+\/proc[^\n]*-name\s+cmdline/,

  // Process memory dumps
  /\bgcore\s+[0-9]/,
  /\bgdb\s+[^\n]*-p\s+[0-9]/,
];

// Password manager patterns
const PASSWORD_MANAGER_PATTERNS = [
  // 1Password
  /\bcat\s+.*1Password.*sqlite/i,
  /\bcp\s+.*1Password.*sqlite/i,
  /\bsqlite3\s+.*1Password/i,
  /\bfind\s+.*1Password.*sqlite/i,

  // LastPass
  /\bcat\s+.*LastPass/i,
  /\bcp\s+.*LastPass/i,
  /\bfind\s+.*LastPass/i,

  // KeePass
  /\bcat\s+.*\.kdbx?\b/,
  /\bcp\s+.*\.kdbx?\b/,
  /\bfind\s+[^\n]*\.kdbx?\b/i,

  // Pass (password-store)
  /\bcat\s+~?\/\.password-store/,
  /\bfind\s+~?\/\.password-store/,
  /\bgpg\s+[^\n]*~?\/\.password-store/,

  // Generic password manager directories
  /\bls\s+-la\s+.*(?:1Password|LastPass|Bitwarden|KeePass)/i,
  /\bfind\s+.*(?:1Password|LastPass|Bitwarden|KeePass)/i,
];

// Database config patterns
const DATABASE_CONFIG_PATTERNS = [
  // MySQL
  /\bcat\s+.*\.my\.cnf\b/,
  /\bcat\s+\/etc\/mysql\/[^\n]*\.cnf\b/,
  /\bgrep\s+[^\n]*password[^\n]*\.my\.cnf\b/i,

  // PostgreSQL
  /\bcat\s+.*\.pgpass\b/,
  /\bcat\s+\/etc\/postgresql[^\n]*\.conf\b/,

  // MongoDB
  /\bcat\s+\/etc\/mongod\.conf\b/,
  /\bgrep\s+[^\n]*password[^\n]*mongod\.conf\b/i,

  // Redis
  /\bcat\s+\/etc\/redis\/redis\.conf\b/,
  /\bgrep\s+[^\n]*requirepass[^\n]*redis\.conf\b/i,

  // General database config
  /\bcat\s+.*database\.yml\b/,
  /\bcat\s+.*db\.conf\b/,
  /\bgrep\s+[^\n]*(?:password|connectionString)[^\n]*\.conf\b/i,
];

// Safe SSH operations that should NOT trigger detection
const SAFE_SSH_OPERATIONS = [
  // ssh-keygen operations (generating keys, not stealing)
  /\bssh-keygen\b/,

  // Reading public keys (safe)
  /\bcat\s+~?\/\.ssh\/id_[^\n]*\.pub\b/,
  /\bcat\s+~?\/\.ssh\/authorized_keys\b/,
  /\bcat\s+~?\/\.ssh\/known_hosts\b/,

  // SSH agent operations
  /\bssh-add\s+-l\b/,
  /\bssh-add\s+-L\b/,

  // Checking SSH config (not credentials)
  /\bcat\s+~?\/\.ssh\/config\b/,

  // Listing SSH directory (not reading keys)
  /\bls\s+[^\n]*~?\/\.ssh\b/,
];

// Safe kubectl operations
const SAFE_KUBECTL_OPERATIONS = [
  // kubectl config view with redacted secrets
  /\bkubectl\s+config\s+view[^\n]*--minify/,
  /\bkubectl\s+config\s+view[^\n]*--flatten/,
  /\bkubectl\s+config\s+get-contexts/,
  /\bkubectl\s+config\s+current-context/,
];

// Safe git operations
const SAFE_GIT_OPERATIONS = [
  // Git config reads that don't expose credentials
  /\bgit\s+config\s+--list/,
  /\bgit\s+config\s+user\./,
  /\bgit\s+config\s+core\./,
  /\bgit\s+config\s+--get\s+(?!credential)/,

  // Git status, log, etc. (safe)
  /\bgit\s+(?:status|log|diff|branch|remote\s+-v)/,
];

/**
 * Check if the command is a safe operation
 */
function isSafeOperation(command: string): boolean {
  return (
    SAFE_SSH_OPERATIONS.some((pattern) => pattern.test(command)) ||
    SAFE_KUBECTL_OPERATIONS.some((pattern) => pattern.test(command)) ||
    SAFE_GIT_OPERATIONS.some((pattern) => pattern.test(command))
  );
}

/**
 * Get the specific credential type being harvested
 */
function getCredentialType(command: string): string {
  if (SSH_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'SSH private keys';
  }
  if (AWS_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'AWS credentials';
  }
  // Check password managers before browser (to avoid false match on "password")
  if (PASSWORD_MANAGER_PATTERNS.some((p) => p.test(command))) {
    return 'password manager databases';
  }
  if (BROWSER_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'browser stored passwords';
  }
  if (DOCKER_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'Docker credentials';
  }
  if (KUBERNETES_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'Kubernetes credentials';
  }
  if (GIT_CREDENTIAL_PATTERNS.some((p) => p.test(command))) {
    return 'Git credentials';
  }
  if (SHELL_HISTORY_PATTERNS.some((p) => p.test(command))) {
    return 'shell history (may contain passwords)';
  }
  if (PROCESS_MEMORY_PATTERNS.some((p) => p.test(command))) {
    return 'process memory (may contain credentials)';
  }
  if (DATABASE_CONFIG_PATTERNS.some((p) => p.test(command))) {
    return 'database configuration files';
  }
  return 'stored credentials';
}

/**
 * Detect credential harvesting attempts
 */
export function detectCredentialHarvesting(
  toolUseData: ToolUseData,
  config?: CredentialHarvestingConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  // Check if this is a safe operation first
  if (isSafeOperation(toolInput)) {
    return Promise.resolve(null);
  }

  // Check all credential harvesting patterns
  const allPatterns = [
    ...SSH_CREDENTIAL_PATTERNS,
    ...AWS_CREDENTIAL_PATTERNS,
    ...BROWSER_CREDENTIAL_PATTERNS,
    ...DOCKER_CREDENTIAL_PATTERNS,
    ...KUBERNETES_CREDENTIAL_PATTERNS,
    ...GIT_CREDENTIAL_PATTERNS,
    ...SHELL_HISTORY_PATTERNS,
    ...PROCESS_MEMORY_PATTERNS,
    ...PASSWORD_MANAGER_PATTERNS,
    ...DATABASE_CONFIG_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    if (pattern.test(toolInput)) {
      const credentialType = getCredentialType(toolInput);
      return Promise.resolve({
        severity,
        message: `Credential harvesting attempt detected: accessing ${credentialType}`,
        detector: 'credential-harvesting',
      });
    }
  }

  return Promise.resolve(null);
}
