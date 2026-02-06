import type { Detection, ToolUseData } from '../types';

/**
 * Detects destructive commands that can cause data loss or system damage
 */

const DESTRUCTIVE_PATTERNS = [
  // rm with dangerous flags
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

  // shred (secure delete)
  /\bshred\b/,

  // Dangerous wildcards in rm
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?[/*]$/,

  // wipefs (wipe filesystem signatures)
  /\bwipefs\b/,

  // Overwrite important system files
  />\s*\/(?:etc\/passwd|etc\/shadow|boot\/|dev\/)/,

  // chmod/chown on critical paths
  /\b(?:chmod|chown)\b[^\n]*(?:\/etc|\/bin|\/sbin|\/usr|\/boot|\/dev|\/sys)/,
];

export function detectDestructiveCommand(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Potentially destructive command detected - could cause data loss or system damage',
        detector: 'destructive-command',
      });
    }
  }

  return Promise.resolve(null);
}
