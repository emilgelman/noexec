import type { Detection, ToolUseData } from '../types';
import type { BackdoorPersistenceConfig } from '../config/types';

/**
 * Detects attempts to establish persistent access to a system
 * 
 * This detector identifies backdoor and persistence mechanisms that attackers
 * use to maintain access even after reboots or cleanup attempts.
 */

// Cron job manipulation patterns
const CRON_PATTERNS = [
  // Cron job editing/creation
  /\bcrontab\s+-e\b/,
  /\bcrontab\s+[^-\s][^\n]*/,  // crontab with file argument
  /\becho\b[^\n]*>>\s*\/etc\/cron\./,
  /\becho\b[^\n]*>\s*\/etc\/cron\./,
  /\bcat\b[^\n]*>>\s*\/etc\/cron\./,
  /\bcat\b[^\n]*>\s*\/etc\/cron\./,
  /\btee\b[^\n]*\/etc\/cron\./,
  // Writing to cron directories
  />\s*\/var\/spool\/cron\//,
  />\s*\/etc\/cron\.d\//,
  />\s*\/etc\/cron\.daily\//,
  />\s*\/etc\/cron\.hourly\//,
  />\s*\/etc\/cron\.weekly\//,
  />\s*\/etc\/cron\.monthly\//,
];

// Systemd service manipulation patterns
const SYSTEMD_PATTERNS = [
  // Enabling services (persistence)
  /\bsystemctl\s+enable\b/,
  /\bsystemctl\s+daemon-reload\b.*\bsystemctl\s+enable\b/,
  // Writing to systemd directories
  />\s*\/etc\/systemd\/system\//,
  />\s*\/lib\/systemd\/system\//,
  />\s*\/usr\/lib\/systemd\/system\//,
  />\s*\/etc\/systemd\/user\//,
  // Creating systemd units
  /\becho\b[^\n]*\.service[^\n]*>\s*\/etc\/systemd/,
  /\bcat\b[^\n]*\.service[^\n]*>\s*\/etc\/systemd/,
  /\btee\b[^\n]*\.service[^\n]*\/etc\/systemd/,
];

// SSH key manipulation patterns
const SSH_KEY_PATTERNS = [
  // Adding to authorized_keys
  /echo\b[^\n]*>>\s*[~\/].*\.ssh\/authorized_keys/,
  /cat\b[^\n]*>>\s*[~\/].*\.ssh\/authorized_keys/,
  /tee\b[^\n]*-a[^\n]*\.ssh\/authorized_keys/,
  />\s*[~\/].*\.ssh\/authorized_keys\b/,
  // SSH key generation and installation
  /ssh-keygen\b.*&&.*authorized_keys/,
  /ssh-copy-id\b/,
  // Writing to SSH directories
  /echo\b[^\n]*>\s*[~\/].*\.ssh\//,
  /cat\b[^\n]*>\s*[~\/].*\.ssh\//,
];

// Shell profile manipulation patterns
const SHELL_PROFILE_PATTERNS = [
  // Modifying shell initialization files
  /echo\b[^\n]*>>\s*[~\/].*\.bashrc\b/,
  /echo\b[^\n]*>>\s*[~\/].*\.bash_profile\b/,
  /echo\b[^\n]*>>\s*[~\/].*\.profile\b/,
  /echo\b[^\n]*>>\s*[~\/].*\.zshrc\b/,
  /echo\b[^\n]*>>\s*[~\/].*\.zprofile\b/,
  /echo\b[^\n]*>>\s*[~\/].*\.zshenv\b/,
  /echo\b[^\n]*>>\s*\/etc\/profile\b/,
  /echo\b[^\n]*>>\s*\/etc\/bash\.bashrc\b/,
  /echo\b[^\n]*>>\s*\/etc\/zsh\/zshrc\b/,
  // Using tee or cat to append
  /tee\b[^\n]*-a[^\n]*\.bashrc\b/,
  /tee\b[^\n]*-a[^\n]*\.zshrc\b/,
  /tee\b[^\n]*-a[^\n]*\.profile\b/,
  /cat\b[^\n]*>>\s*[~\/].*\.bashrc\b/,
  /cat\b[^\n]*>>\s*[~\/].*\.zshrc\b/,
  /cat\b[^\n]*>>\s*[~\/].*\.profile\b/,
];

// Startup script manipulation patterns
const STARTUP_SCRIPT_PATTERNS = [
  // rc.local manipulation
  /echo\b[^\n]*>>\s*\/etc\/rc\.local\b/,
  /cat\b[^\n]*>>\s*\/etc\/rc\.local\b/,
  /tee\b[^\n]*-a[^\n]*\/etc\/rc\.local\b/,
  />\s*\/etc\/rc\.local\b/,
  // init.d scripts
  />\s*\/etc\/init\.d\//,
  /echo\b[^\n]*>\s*\/etc\/init\.d\//,
  /cat\b[^\n]*>\s*\/etc\/init\.d\//,
  // Autostart directories
  />\s*[~\/].*\.config\/autostart\//,
  /echo\b[^\n]*>\s*[~\/].*\.config\/autostart\//,
  /cat\b[^\n]*>\s*[~\/].*\.config\/autostart\//,
  // XDG autostart
  />\s*\/etc\/xdg\/autostart\//,
];

// SUID binary manipulation patterns
const SUID_PATTERNS = [
  // Setting SUID bit
  /\bchmod\s+(?:[0-7]*[4567][0-7]{3}|u\+s|[ugoa]+.*\+s)\b/,
  // Setting SUID on binaries
  /\bchmod\b[^\n]*\+s[^\n]*\/(?:bin|sbin|usr)\b/,
  // Setting SUID on shells (common backdoor)
  /\bchmod\b[^\n]*\+s[^\n]*\/(?:bin\/)?(?:bash|sh|zsh|dash|ksh|fish)\b/,
];

// LD_PRELOAD manipulation patterns
const LD_PRELOAD_PATTERNS = [
  // Setting LD_PRELOAD environment variable
  /\bexport\s+LD_PRELOAD\s*=/,
  /\bLD_PRELOAD\s*=[^\s]*/,
  // Writing to ld.so.preload
  /echo\b[^\n]*>>\s*\/etc\/ld\.so\.preload\b/,
  /cat\b[^\n]*>>\s*\/etc\/ld\.so\.preload\b/,
  /tee\b[^\n]*-a[^\n]*\/etc\/ld\.so\.preload\b/,
  />\s*\/etc\/ld\.so\.preload\b/,
  // LD_LIBRARY_PATH manipulation
  /\bexport\s+LD_LIBRARY_PATH\s*=/,
];

// Login manipulation patterns
const LOGIN_MANIPULATION_PATTERNS = [
  // Modifying /etc/passwd
  /echo\b[^\n]*>>\s*\/etc\/passwd\b/,
  /cat\b[^\n]*>>\s*\/etc\/passwd\b/,
  /tee\b[^\n]*-a[^\n]*\/etc\/passwd\b/,
  /sed\b[^\n]*\/etc\/passwd\b/,
  /awk\b[^\n]*>\s*\/etc\/passwd\b/,
  /perl\b[^\n]*>\s*\/etc\/passwd\b/,
  // Modifying /etc/shadow
  /echo\b[^\n]*>>\s*\/etc\/shadow\b/,
  /cat\b[^\n]*>>\s*\/etc\/shadow\b/,
  /tee\b[^\n]*-a[^\n]*\/etc\/shadow\b/,
  /sed\b[^\n]*\/etc\/shadow\b/,
  // PAM configuration manipulation
  />\s*\/etc\/pam\.d\//,
  /echo\b[^\n]*>\s*\/etc\/pam\.d\//,
];

// Browser extension patterns
const BROWSER_EXTENSION_PATTERNS = [
  // Chrome/Chromium extensions - paths
  /\.config\/google-chrome\/.*\/Extensions\//,
  /\.config\/chromium\/.*\/Extensions\//,
  /chrome\s+--load-extension\b/,
  /chromium\s+--load-extension\b/,
  /google-chrome\s+--load-extension\b/,
  // Firefox extensions - paths
  /\.mozilla\/firefox\/.*\/extensions\//,
  /firefox\s+.*\.xpi\b/,
  // Extension installation commands
  /\bchrome-cli\s+install\b/,
  /\bweb-ext\s+(?:install|run)\b/,
];

// At/batch job scheduling patterns
const AT_BATCH_PATTERNS = [
  // At job scheduling
  /\bat\b\s+(?:now|[0-9]|tomorrow|midnight|noon)/,
  /\bat\b\s+-f\b/,
  /\becho\b[^\n]*\|\s*\bat\b/,
  /\bat\b.*<<\s*EOF/,
  // Batch scheduling
  /\bbatch\b\s+(?:now|[0-9])/,
  /\bbatch\b\s+-f\b/,
  /\becho\b[^\n]*\|\s*\bbatch\b/,
];

// Safe operations that shouldn't trigger detection
const SAFE_PATTERNS = [
  // Reading crontab (not modifying)
  /^crontab\s+-l\s*$/,
  /^crontab\s+-l\s+(-u\s+\w+\s*)?$/,
  // Checking systemd status (not enabling)
  /^systemctl\s+status\b/,
  /^systemctl\s+show\b/,
  /^systemctl\s+list-units\b/,
  /^systemctl\s+cat\b/,
  /^systemctl\s+is-enabled\b/,
  /^systemctl\s+is-active\b/,
  // Reading SSH keys (not adding)
  /^cat\s+[~\/].*\.ssh\/authorized_keys\s*$/,
  /^less\s+[~\/].*\.ssh\/authorized_keys\s*$/,
  /^more\s+[~\/].*\.ssh\/authorized_keys\s*$/,
  /^head\s+[~\/].*\.ssh\/authorized_keys\s*$/,
  /^tail\s+[~\/].*\.ssh\/authorized_keys\s*$/,
  // Reading shell profiles (not modifying)
  /^cat\s+[~\/].*\.bashrc\s*$/,
  /^cat\s+[~\/].*\.zshrc\s*$/,
  /^less\s+[~\/].*\.(bashrc|zshrc|profile)\s*$/,
  // Listing at jobs (not creating)
  /^atq\s*$/,
  /^at\s+-l\s*$/,
];

/**
 * Check if the command is a safe operation
 */
function isSafeOperation(command: string): boolean {
  const trimmedCommand = command.trim();
  
  for (const pattern of SAFE_PATTERNS) {
    if (pattern.test(trimmedCommand)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Get a specific message based on the detected pattern
 */
function getDetectionMessage(toolInput: string): string {
  if (CRON_PATTERNS.some(p => p.test(toolInput))) {
    return 'Cron job manipulation detected - potential persistence mechanism';
  }
  
  if (SYSTEMD_PATTERNS.some(p => p.test(toolInput))) {
    return 'Systemd service manipulation detected - potential persistence mechanism';
  }
  
  if (SSH_KEY_PATTERNS.some(p => p.test(toolInput))) {
    return 'SSH key manipulation detected - potential backdoor access';
  }
  
  if (SHELL_PROFILE_PATTERNS.some(p => p.test(toolInput))) {
    return 'Shell profile modification detected - potential persistence mechanism';
  }
  
  if (STARTUP_SCRIPT_PATTERNS.some(p => p.test(toolInput))) {
    return 'Startup script manipulation detected - potential persistence mechanism';
  }
  
  if (SUID_PATTERNS.some(p => p.test(toolInput))) {
    return 'SUID bit manipulation detected - potential privilege escalation backdoor';
  }
  
  if (LD_PRELOAD_PATTERNS.some(p => p.test(toolInput))) {
    return 'LD_PRELOAD manipulation detected - potential library injection backdoor';
  }
  
  if (LOGIN_MANIPULATION_PATTERNS.some(p => p.test(toolInput))) {
    return 'Login system manipulation detected - potential backdoor account creation';
  }
  
  if (BROWSER_EXTENSION_PATTERNS.some(p => p.test(toolInput))) {
    return 'Browser extension installation detected - potential persistence mechanism';
  }
  
  if (AT_BATCH_PATTERNS.some(p => p.test(toolInput))) {
    return 'Scheduled job creation detected - potential persistence mechanism';
  }
  
  return 'Backdoor/persistence mechanism detected';
}

/**
 * Detect backdoor and persistence mechanisms
 */
export function detectBackdoorPersistence(
  toolUseData: ToolUseData,
  config?: BackdoorPersistenceConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'critical';
  const toolInput = JSON.stringify(toolUseData);

  // Check for safe operations first
  if (toolUseData.command && isSafeOperation(toolUseData.command)) {
    return Promise.resolve(null);
  }

  // Check all pattern categories
  const allPatterns = [
    ...CRON_PATTERNS,
    ...SYSTEMD_PATTERNS,
    ...SSH_KEY_PATTERNS,
    ...SHELL_PROFILE_PATTERNS,
    ...STARTUP_SCRIPT_PATTERNS,
    ...SUID_PATTERNS,
    ...LD_PRELOAD_PATTERNS,
    ...LOGIN_MANIPULATION_PATTERNS,
    ...BROWSER_EXTENSION_PATTERNS,
    ...AT_BATCH_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message: getDetectionMessage(toolInput),
        detector: 'backdoor-persistence',
      });
    }
  }

  return Promise.resolve(null);
}
