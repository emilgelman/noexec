import type { Detection, ToolUseData } from '../types';
import type { BinaryDownloadExecuteConfig } from '../config/types';

/**
 * Detects dangerous patterns where code is downloaded and executed without verification
 */

/**
 * Patterns for pipe-to-shell execution
 */
const PIPE_TO_SHELL_PATTERNS = [
  // curl | bash/sh/zsh/fish variations
  /\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b/,
  /\bcurl\b[^\n|]*\|\s*(?:zsh|fish|ksh)\b/,

  // wget -O- | shell variations
  /\bwget\b[^\n|]*(?:-O-|--output-document=-)[^\n|]*\|\s*(?:ba)?sh\b/,
  /\bwget\b[^\n|]*(?:-O-|--output-document=-)[^\n|]*\|\s*(?:zsh|fish|ksh)\b/,

  // Pipe to interpreters (python, perl, ruby, node)
  /\bcurl\b[^\n|]*\|\s*(?:python[0-9.]*|perl|ruby|node|php)\b/,
  /\bwget\b[^\n|]*(?:-O-|--output-document=-)[^\n|]*\|\s*(?:python[0-9.]*|perl|ruby|node|php)\b/,

  // With sudo
  /\bcurl\b[^\n|]*\|\s*sudo\s+(?:ba)?sh\b/,
  /\bwget\b[^\n|]*(?:-O-|--output-document=-)[^\n|]*\|\s*sudo\s+(?:ba)?sh\b/,
  /\bcurl\b[^\n|]*\|\s*sudo\s+(?:python[0-9.]*|perl|ruby)\b/,

  // fetch variations (HTTP clients)
  /\bfetch\b[^\n|]*\|\s*(?:ba)?sh\b/,
  /\bhttp\b[^\n|]*\|\s*(?:ba)?sh\b/,

  // Base64 encoded downloads and execute
  /\bcurl\b[^\n|]*\|\s*base64\s+-d\s*\|\s*(?:ba)?sh\b/,
  /\bwget\b[^\n|]*\|\s*base64\s+-d\s*\|\s*(?:ba)?sh\b/,

  // Variations with parentheses: $(curl ...) | bash
  /\$\(\s*(?:curl|wget)\b[^)]*\)\s*\|\s*(?:ba)?sh\b/,
];

/**
 * Patterns for download + execute chains
 */
const DOWNLOAD_EXECUTE_CHAINS = [
  // wget file && chmod +x && ./file
  /\bwget\b[^\n&;]*&&[^\n&;]*\bchmod\b[^\n&;]*\+x[^\n&;]*&&[^\n&;]*\.\//,

  // curl -o file && chmod +x && ./file
  /\bcurl\b[^\n&;]*(?:-o|--output)[^\n&;]*&&[^\n&;]*\bchmod\b[^\n&;]*\+x[^\n&;]*&&[^\n&;]*\.\//,

  // wget file; chmod +x; ./file
  /\bwget\b[^\n;]*;[^\n;]*\bchmod\b[^\n;]*\+x[^\n;]*;[^\n;]*\.\//,

  // curl file; chmod +x; ./file
  /\bcurl\b[^\n;]*(?:-o|--output)[^\n;]*;[^\n;]*\bchmod\b[^\n;]*\+x[^\n;]*;[^\n;]*\.\//,

  // Download to /tmp and execute
  /\b(?:wget|curl)\b[^\n&;]*(?:\/tmp|\/dev\/shm)[^\n&;]*&&[^\n&;]*\.\//,
];

/**
 * Patterns for executing from dangerous locations
 */
const DANGEROUS_LOCATION_EXECUTION = [
  // Executing scripts from /tmp
  /(?:ba)?sh\s+\/tmp\/[^\s]+/,
  /python[0-9.]*\s+\/tmp\/[^\s]+/,
  /perl\s+\/tmp\/[^\s]+/,
  /ruby\s+\/tmp\/[^\s]+/,

  // Executing scripts from /dev/shm
  /(?:ba)?sh\s+\/dev\/shm\/[^\s]+/,
  /python[0-9.]*\s+\/dev\/shm\/[^\s]+/,

  // chmod +x in dangerous locations
  /\bchmod\b[^\n]*\+x[^\n]*(?:\/tmp|\/dev\/shm|~\/\.cache)/,

  // Direct execution from dangerous locations
  /\.\/[^\s]+\s+&&\s+\.\//,
  /\/tmp\/[^\s]+\s*$/,
  /\/dev\/shm\/[^\s]+\s*$/,
];

/**
 * Patterns for unsafe install scripts
 */
const UNSAFE_INSTALL_SCRIPTS = [
  // curl install.sh | bash variations
  /\bcurl\b[^\n|]*install[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
  /\bwget\b[^\n|]*install[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,

  // get.sh, setup.sh patterns (common install script names)
  /\bcurl\b[^\n|]*(?:get|setup|bootstrap|init)\.sh[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
  /\bwget\b[^\n|]*(?:get|setup|bootstrap|init)\.sh[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,

  // curl -sSL ... | sudo bash (common pattern)
  /\bcurl\b[^\n]*(?:-sSL|-fsSL|-sS)[^\n|]*\|\s*sudo\s+(?:ba)?sh\b/,
];

/**
 * Patterns for following redirects to executables
 */
const REDIRECT_EXECUTE_PATTERNS = [
  // curl -L (follow redirects) to pipe
  /\bcurl\b[^\n]*(?:-L|--location)[^\n|]*\|\s*(?:ba)?sh\b/,
  /\bcurl\b[^\n]*(?:-L|--location)[^\n|]*\|\s*(?:python[0-9.]*|perl|ruby)\b/,

  // wget with redirects
  /\bwget\b[^\n]*(?:--max-redirect|--trust-server-names)[^\n|]*\|\s*(?:ba)?sh\b/,
];

/**
 * Safe patterns - package managers and known safe install methods
 */
const SAFE_PATTERNS = [
  // Package managers
  /\b(?:apt|apt-get|yum|dnf|pacman|brew|npm|pip|cargo|gem)\s+install\b/,

  // rustup, nvm, etc. (established install tools)
  /\bcurl\b[^\n]*https:\/\/sh\.rustup\.rs[^\n]*\|\s*sh\b/,
  /\bcurl\b[^\n]*https:\/\/raw\.githubusercontent\.com\/nvm-sh\/nvm[^\n]*\|\s*bash\b/,

  // Official Docker install
  /\bcurl\b[^\n]*get\.docker\.com[^\n]*\|\s*sh\b/,

  // Homebrew install
  /\bcurl\b[^\n]*https:\/\/raw\.githubusercontent\.com\/Homebrew\/install[^\n]*\|\s*bash\b/,

  // asdf version manager
  /\bgit clone\b[^\n]*asdf-vm\/asdf/,

  // pyenv install
  /\bcurl\b[^\n]*pyenv\.run[^\n]*\|\s*bash\b/,
];

/**
 * Check if a command matches safe installation patterns
 */
function isSafeInstall(command: string): boolean {
  return SAFE_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Detect binary download and execute patterns
 */
export function detectBinaryDownloadExecute(
  toolUseData: ToolUseData,
  config?: BinaryDownloadExecuteConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const trustedDomains = config?.trustedDomains ?? [];
  const toolInput = JSON.stringify(toolUseData);

  // Check if this is a safe install pattern
  if (isSafeInstall(toolInput)) {
    return Promise.resolve(null);
  }

  // Check for trusted domains (if configured)
  if (trustedDomains.length > 0) {
    const hasTrustedDomain = trustedDomains.some((domain) => {
      const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pattern = new RegExp(`https?://[^/]*${escapedDomain}`, 'i');
      return pattern.test(toolInput);
    });

    if (hasTrustedDomain) {
      return Promise.resolve(null);
    }
  }

  // Check pipe-to-shell patterns (HIGH PRIORITY)
  for (const pattern of PIPE_TO_SHELL_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Dangerous pattern: downloading and piping to shell/interpreter without verification - could execute malicious code',
        detector: 'binary-download-execute',
      });
    }
  }

  // Check download + execute chains
  for (const pattern of DOWNLOAD_EXECUTE_CHAINS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Dangerous pattern: downloading file, making it executable, and running it without verification',
        detector: 'binary-download-execute',
      });
    }
  }

  // Check execution from dangerous locations
  for (const pattern of DANGEROUS_LOCATION_EXECUTION) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Dangerous pattern: executing code from temporary/cache directory (/tmp, /dev/shm) - common malware technique',
        detector: 'binary-download-execute',
      });
    }
  }

  // Check unsafe install scripts
  for (const pattern of UNSAFE_INSTALL_SCRIPTS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Dangerous pattern: downloading install script and executing with elevated privileges without verification',
        detector: 'binary-download-execute',
      });
    }
  }

  // Check redirect-to-execute patterns
  for (const pattern of REDIRECT_EXECUTE_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Dangerous pattern: following redirects and piping to shell - redirect destination may be malicious',
        detector: 'binary-download-execute',
      });
    }
  }

  return Promise.resolve(null);
}
