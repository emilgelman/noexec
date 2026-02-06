import type { Detection, ToolUseData } from '../types';
import type { DestructiveCommandsConfig } from '../config/types';

/**
 * Detects destructive commands that can cause data loss or system damage
 */

// Safe paths that can be removed without major consequences
const SAFE_PATHS = [
  /^\.\/node_modules/,
  /^\.\/dist/,
  /^\.\/build/,
  /^\.\/target/,
  /^\.\/out/,
  /^\.\/coverage/,
  /^\.?\/?tmp\//,
  /^\.?\/?temp\//,
  /^\.\/\..+\//, // Hidden directories in current dir (like ./.next/, ./.cache/)
];

const DESTRUCTIVE_PATTERNS = [
  // rm with dangerous flags and paths
  /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+|\s+-[a-zA-Z]*[rf])[^\n]*(\/|~|\*|\$HOME)/,

  // dd command (disk operations)
  /\bdd\s+[^\n]*(?:if=|of=)(?:\/dev\/|\/|~)/,

  // mkfs (format filesystem)
  /\bmkfs\b/,

  // fdisk, parted (partition editing)
  /\b(?:fdisk|parted|gpart)\b/,

  // Fork bomb variations
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  /\.\/\$0\s*&\s*\.\/\$0/,
  /\bwhile\s+true\s*;\s*do\s+.+\s*&\s*done/,

  // shred (secure delete)
  /\bshred\b/,

  // Dangerous wildcards in rm
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?[/*]$/,

  // wipefs (wipe filesystem signatures)
  /\bwipefs\b/,

  // Overwrite important system files
  />\s*\/(?:etc\/passwd|etc\/shadow|boot\/|dev\/)/,

  // chmod/chown on critical paths
  /\b(?:chmod|chown)\b[^\n]*(?:\/etc|\/bin|\/sbin|\/usr\/bin|\/usr\/sbin|\/boot|\/dev|\/sys)/,

  // Disk filling attacks
  /\bdd\s+if=\/dev\/zero/,
  /\byes\s*\|/,
  /:\(\)\{\s*:\|:&\s*\};:/,

  // Mass process killers
  /\bkill(?:all)?\s+(?:-9\s+)?-1\b/,
  /\bpkill\s+(?:-9\s+)?-[Uu]\s+/,
  /\bkill\s+-9\s+\$\(ps\s+-A/,

  // Network disruption
  /\biptables\s+-F\b/,
  /\bip\s+link\s+set\s+\w+\s+down\b/,
  /\bifconfig\s+\w+\s+down\b/,

  // Init system manipulation
  /\bsystemctl\s+(?:stop|disable)\s+(?:sshd|networking|firewalld)\b/,
  /\bservice\s+(?:ssh|network)\s+stop\b/,

  // Kernel panic / system crash
  /\becho\s+[cb]\s*>\s*\/proc\/sysrq-trigger/,

  // Cron job deletion
  /\bcrontab\s+-r\b/,
];

/**
 * Check if a path is in the safe list
 */
function isSafePath(path: string, safePaths: string[]): boolean {
  // Convert string patterns to regex
  const safePatterns = safePaths.map((pattern) => {
    // If it looks like a regex-friendly pattern, use it; otherwise escape it
    if (pattern.includes('*') || pattern.includes('.')) {
      return new RegExp(pattern.replace(/\./g, '\\.').replace(/\*/g, '.*'));
    }
    return new RegExp(`^${pattern.replace(/\//g, '\\/')}`);
  });

  for (const safePattern of safePatterns) {
    if (safePattern.test(path)) {
      return true;
    }
  }

  // Also check built-in safe paths
  for (const safePattern of SAFE_PATHS) {
    if (safePattern.test(path)) {
      return true;
    }
  }

  return false;
}

/**
 * Extract path from rm command for safety check
 */
function extractRmPath(command: string): string | null {
  // Match rm -rf <path> or rm -r <path>
  const match = /\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+([^\s;|&]+)/.exec(command);
  return match ? match[1] : null;
}

export function detectDestructiveCommand(
  toolUseData: ToolUseData,
  config?: DestructiveCommandsConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const safePaths = config?.safePaths ?? [];
  const additionalPatterns = config?.additionalPatterns ?? [];
  const severity = config?.severity ?? 'high';

  const toolInput = JSON.stringify(toolUseData);

  // Special handling for rm commands - check if path is safe
  if (/\brm\s+-[a-zA-Z]*r[a-zA-Z]*/.test(toolInput)) {
    const path = extractRmPath(toolInput);
    if (path && isSafePath(path, safePaths)) {
      // This is a safe rm operation (like rm -rf ./node_modules)
      return Promise.resolve(null);
    }
  }

  // Check additional custom patterns
  for (const patternStr of additionalPatterns) {
    try {
      const pattern = new RegExp(patternStr);
      if (pattern.test(toolInput)) {
        return Promise.resolve({
          severity,
          message: 'Custom destructive pattern detected',
          detector: 'destructive-command',
        });
      }
    } catch {
      // Invalid regex pattern, skip it
      console.warn(`Invalid additional pattern: ${patternStr}`);
    }
  }

  // Check built-in destructive patterns
  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Potentially destructive command detected - could cause data loss or system damage',
        detector: 'destructive-command',
      });
    }
  }

  return Promise.resolve(null);
}
