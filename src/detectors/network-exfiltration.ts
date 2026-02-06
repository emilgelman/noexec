import type { Detection, ToolUseData } from '../types';

// Network commands commonly used for exfiltration
const NETWORK_COMMANDS = [
  /\b(?:curl|wget|nc|ncat|netcat|telnet|socat)\b/,
  /\bhttpie?(?:\s|$)/, // http/httpie command
  /\/dev\/tcp\//,
  /\/dev\/udp\//,
];

// Commands that read sensitive files
const FILE_READ_COMMANDS = [
  /\b(?:cat|head|tail|grep|awk|sed|cut|sort|uniq)\b/,
  /\bless\s+(?!-)/,
  /\bmore\s+(?!-)/,
  /\btac\b/,
  /\bnl\b/,
];

// Encoding commands often used to obfuscate data
const ENCODING_COMMANDS = [
  /\bbase64\b/,
  /\bxxd\b/,
  /\bhexdump\b/,
  /\bod\b/,
  /\buuencode\b/,
  /\bgzip\b.*\bbase64\b/,
];

// Sensitive file patterns
const SENSITIVE_FILE_PATTERNS = [
  /\.env(?:\.[a-z]+)?/,
  /\.aws\/credentials/,
  /\.ssh\/id_[rd]sa/,
  /\.ssh\/.*\.pem/,
  /\.npmrc/,
  /\.pypirc/,
  /\.dockercfg/,
  /\.docker\/config\.json/,
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\/etc\/hosts/,
  /secret/i,
  /password/i,
  /credential/i,
  /private[_-]?key/i,
  /api[_-]?key/i,
  /token/i,
  /\.pem$/,
  /\.key$/,
  /\.crt$/,
];

// DNS exfiltration patterns
const DNS_EXFILTRATION_PATTERNS = [
  // dig/nslookup with command substitution
  /\b(?:dig|nslookup|host)\s+.*\$\(/,
  /\b(?:dig|nslookup|host)\s+.*`/,
  // DNS query with encoded data
  /\b(?:dig|nslookup|host)\s+.*\.(?:[a-z0-9-]+\.){2,}/,
];

// Reverse shell patterns
const REVERSE_SHELL_PATTERNS = [
  // bash/sh reverse shells
  /bash\s+-i\s*>?\s*&\s*\/dev\/tcp\//,
  /sh\s+-i\s*>?\s*&\s*\/dev\/tcp\//,
  /exec\s+\d+<>\/dev\/tcp\//,
  /0<&\d+/,
  // nc reverse shells
  /\bnc\b.*-e\s*(?:\/bin\/bash|\/bin\/sh|bash|sh)/,
  /\b(?:nc|ncat|netcat)\b.*\|.*(?:\/bin\/bash|\/bin\/sh|bash|sh)/,
  // perl/python/ruby reverse shells
  /perl.*socket.*exec/i,
  /python.*socket.*subprocess/i,
  /ruby.*socket.*exec/i,
  // mkfifo reverse shells
  /mkfifo.*nc\b/,
  /mkfifo.*\/dev\/tcp\//,
];

// Suspicious network destinations
const SUSPICIOUS_DESTINATIONS = [
  // Hidden directories (often used for malware staging)
  /\/dev\/shm\//,
  /\/tmp\/\./,
  /\/var\/tmp\/\./,
  // Paste sites / webhook services (common for exfiltration)
  /pastebin\.com/,
  /paste\.ee/,
  /hastebin\.com/,
  /dpaste\.com/,
  /ix\.io/,
  /sprunge\.us/,
  /termbin\.com/,
  /discord\.com\/api\/webhooks\//,
  /discordapp\.com\/api\/webhooks\//,
  /hooks\.slack\.com/,
  /api\.telegram\.org\/bot/,
  // Raw IP addresses (suspicious in automated contexts)
  /(?:curl|wget|nc|telnet)\b.*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
];

// HTTP POST patterns (uploading data)
const HTTP_POST_PATTERNS = [
  /curl.*-X\s*POST/,
  /curl.*--data/,
  /curl.*-d\s/,
  /curl.*--form/,
  /curl.*-F\s/,
  /wget.*--post-/,
  /http\s+POST/,
];

// File upload patterns
const FILE_UPLOAD_PATTERNS = [
  /curl.*-F\s+.*file=@/,
  /curl.*--form.*file=@/,
  /curl.*--upload-file/,
  /curl.*-T\s/,
  /wget.*--post-file/,
];

// Git suspicious remote patterns
const GIT_SUSPICIOUS_PATTERNS = [
  // Adding new remote followed by push
  /git\s+remote\s+add.*(?:\n|;|&&).*git\s+push/,
  // Push to non-github/gitlab/bitbucket
  /git\s+push.*(?!github\.com|gitlab\.com|bitbucket\.org)/,
  // Push with raw credentials in URL
  /git\s+push.*https?:\/\/[^@\s]+:[^@\s]+@/,
];

/**
 * Check if command contains piped network operations
 * Pattern: reading something | network command
 */
function hasPipedNetworkOperation(command: string): boolean {
  // Split by pipe, check if any segment has file reading followed by network
  const segments = command.split('|');
  if (segments.length < 2) return false;

  for (let i = 0; i < segments.length - 1; i++) {
    const current = segments[i];
    const next = segments[i + 1];

    // Check if current segment reads data
    const readsData =
      FILE_READ_COMMANDS.some((p) => p.test(current)) ||
      SENSITIVE_FILE_PATTERNS.some((p) => p.test(current));

    // Check if next segment sends to network
    const sendsToNetwork = NETWORK_COMMANDS.some((p) => p.test(next));

    if (readsData && sendsToNetwork) {
      return true;
    }
  }

  return false;
}

/**
 * Check if command contains encoding + network transmission
 * Pattern: data | base64 | curl
 */
function hasEncodedNetworkTransmission(command: string): boolean {
  const hasEncoding = ENCODING_COMMANDS.some((p) => p.test(command));
  const hasNetwork = NETWORK_COMMANDS.some((p) => p.test(command));
  const hasPipe = command.includes('|');

  return hasEncoding && hasNetwork && hasPipe;
}

/**
 * Check if command reads sensitive files
 */
function readsSensitiveFile(command: string): boolean {
  return SENSITIVE_FILE_PATTERNS.some((p) => p.test(command));
}

/**
 * Check if command contains DNS exfiltration patterns
 */
function hasDNSExfiltration(command: string): boolean {
  return DNS_EXFILTRATION_PATTERNS.some((p) => p.test(command));
}

/**
 * Check if command contains reverse shell patterns
 */
function hasReverseShell(command: string): boolean {
  return REVERSE_SHELL_PATTERNS.some((p) => p.test(command));
}

/**
 * Check if command sends data to suspicious destinations
 */
function hasSuspiciousDestination(command: string): boolean {
  return SUSPICIOUS_DESTINATIONS.some((p) => p.test(command));
}

/**
 * Check if command contains HTTP POST with sensitive data
 */
function hasHTTPPostWithSensitiveData(command: string): boolean {
  const hasPost = HTTP_POST_PATTERNS.some((p) => p.test(command));
  const hasSensitiveFile = readsSensitiveFile(command);

  return hasPost && hasSensitiveFile;
}

/**
 * Check if command uploads files via HTTP
 */
function hasFileUpload(command: string): boolean {
  return FILE_UPLOAD_PATTERNS.some((p) => p.test(command));
}

/**
 * Check if command contains suspicious git operations
 */
function hasSuspiciousGitRemote(command: string): boolean {
  return GIT_SUSPICIOUS_PATTERNS.some((p) => p.test(command));
}

/**
 * Check if network operation is likely safe
 * Safe patterns: API calls, package managers, common dev tools
 */
function isSafeNetworkOperation(command: string): boolean {
  const safePatterns = [
    // Package managers
    /npm\s+(?:install|update|publish)/,
    /yarn\s+(?:add|install|publish)/,
    /pnpm\s+(?:add|install)/,
    /pip\s+install/,
    /cargo\s+(?:install|publish)/,
    /gem\s+install/,
    /go\s+get/,

    // Common dev tools
    /curl.*api\.github\.com/,
    /curl.*registry\.npmjs\.org/,
    /wget.*pypi\.org/,
    /git\s+clone\s+https:\/\/github\.com/,
    /git\s+clone\s+https:\/\/gitlab\.com/,
    /git\s+clone\s+https:\/\/bitbucket\.org/,

    // Health checks / monitoring (without reading files first)
    /^curl\s+-[fsSL]*\s+https?:\/\/(?!.*\$)/, // Simple GET without vars
    /^wget\s+-[qO]*\s+https?:\/\/(?!.*\$)/,

    // Docker registry
    /docker\s+(?:pull|push)/,
  ];

  return safePatterns.some((p) => p.test(command));
}

export function detectNetworkExfiltration(toolUseData: ToolUseData): Promise<Detection | null> {
  const command = toolUseData.command ?? '';

  // Skip empty commands
  if (!command.trim()) {
    return Promise.resolve(null);
  }

  // Check for safe patterns first
  if (isSafeNetworkOperation(command)) {
    return Promise.resolve(null);
  }

  // Check for reverse shells (highest priority)
  if (hasReverseShell(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Reverse shell detected - potential remote access attempt',
      detector: 'network-exfiltration',
    });
  }

  // Check for DNS exfiltration
  if (hasDNSExfiltration(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'DNS exfiltration pattern detected - data may be leaked via DNS queries',
      detector: 'network-exfiltration',
    });
  }

  // Check for piped network operations (cat secret | nc)
  if (hasPipedNetworkOperation(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Data piped to network command - potential exfiltration',
      detector: 'network-exfiltration',
    });
  }

  // Check for encoded network transmission (cat | base64 | curl)
  if (hasEncodedNetworkTransmission(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Encoded data transmission detected - potential obfuscated exfiltration',
      detector: 'network-exfiltration',
    });
  }

  // Check for HTTP POST with sensitive data
  if (hasHTTPPostWithSensitiveData(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'HTTP POST of sensitive file detected - potential credential theft',
      detector: 'network-exfiltration',
    });
  }

  // Check for file upload patterns
  if (hasFileUpload(command) && readsSensitiveFile(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Sensitive file upload detected - potential data exfiltration',
      detector: 'network-exfiltration',
    });
  }

  // Check for suspicious destinations
  if (hasSuspiciousDestination(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Suspicious network destination detected (pastebin, webhook, or hidden location)',
      detector: 'network-exfiltration',
    });
  }

  // Check for suspicious git operations
  if (hasSuspiciousGitRemote(command)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Suspicious git remote operation - potential code exfiltration',
      detector: 'network-exfiltration',
    });
  }

  return Promise.resolve(null);
}
