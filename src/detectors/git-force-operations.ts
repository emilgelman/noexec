import type { Detection, ToolUseData } from '../types';
import type { GitForceOperationsConfig } from '../config/types';

/**
 * Detects dangerous git operations that can cause data loss or collaboration issues
 */

// Protected branches that should never be force-pushed (customizable)
const PROTECTED_BRANCHES = ['main', 'master', 'production', 'prod', 'release'];

const GIT_DANGEROUS_PATTERNS = [
  // Force push (but NOT force-with-lease, which is safer)
  /\bgit\s+push\s+[^\n]*--force(?!-with-lease\b)/,
  /\bgit\s+push\s+[^\n]*-f\s/,

  // Hard reset (destroys local changes)
  /\bgit\s+reset\s+--hard/,

  // Clean with force (removes untracked files)
  /\bgit\s+clean\s+[^\n]*-[a-zA-Z]*f[a-zA-Z]*(?:\s+[^\n]*-[a-zA-Z]*[dx])?/,

  // Force checkout (discards local changes)
  /\bgit\s+checkout\s+[^\n]*--force/,
  /\bgit\s+checkout\s+[^\n]*-f\s/,

  // Note: git branch -D (local branch deletion) is intentionally NOT included
  // as it only affects local branches and is a common, safe operation

  // Prune with dangerous flags
  /\bgit\s+(?:remote\s+)?prune\s+[^\n]*--force/,

  // Filter-branch (rewrites history)
  /\bgit\s+filter-branch/,

  // Reflog expire/delete
  /\bgit\s+reflog\s+(?:expire|delete)/,

  // Update-ref -d (delete refs)
  /\bgit\s+update-ref\s+-d/,

  // Interactive rebase (can rewrite history)
  /\bgit\s+rebase\s+(?:-i|--interactive)\b/,

  // Rebase with skip (potentially dangerous)
  /\bgit\s+rebase\s+--skip\b/,

  // Force-delete remote branch
  /\bgit\s+push\s+[^\n]*:[^\s]+/,
];

/**
 * Extract branch name from git push command
 */
function extractPushBranch(command: string): string | null {
  // Try to match: git push origin branch-name
  const match = /\bgit\s+push\s+[^\n]*\s+([a-zA-Z0-9/_-]+)/.exec(command);
  return match?.[1] ?? null;
}

/**
 * Check if force push is to a protected branch
 */
function isForceToProtectedBranch(command: string, protectedBranches: string[]): boolean {
  const branch = extractPushBranch(command);
  if (!branch) return false;

  return protectedBranches.some((protected_) => branch === protected_);
}

/**
 * Determine severity based on context
 */
function getSeverity(command: string, protectedBranches: string[]): 'high' | 'medium' {
  // Force push to main/master/production is HIGH severity
  if (
    /\bgit\s+push.*--force/.test(command) &&
    isForceToProtectedBranch(command, protectedBranches)
  ) {
    return 'high';
  }

  // Interactive rebase is medium (useful but risky)
  if (/\bgit\s+rebase\s+(?:-i|--interactive)/.test(command)) {
    return 'medium';
  }

  // Most other operations are high
  return 'high';
}

export function detectGitForceOperation(
  toolUseData: ToolUseData,
  config?: GitForceOperationsConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const protectedBranches = config?.protectedBranches ?? PROTECTED_BRANCHES;
  const allowForceWithLease = config?.allowForceWithLease ?? true;
  const configSeverity = config?.severity ?? 'high';

  const toolInput = JSON.stringify(toolUseData);

  // If force-with-lease is allowed, skip those patterns
  if (allowForceWithLease && /\bgit\s+push\s+[^\n]*--force-with-lease/.test(toolInput)) {
    return Promise.resolve(null);
  }

  for (const pattern of GIT_DANGEROUS_PATTERNS) {
    if (pattern.test(toolInput)) {
      const severity = getSeverity(toolInput, protectedBranches);
      // Use config severity if explicitly set, otherwise use calculated severity
      const finalSeverity = config?.severity ? configSeverity : severity;

      return Promise.resolve({
        severity: finalSeverity,
        message:
          severity === 'high'
            ? 'Dangerous git operation detected - can cause data loss or overwrite remote history'
            : 'Git operation detected that rewrites history - use with caution',
        detector: 'git-force-operation',
      });
    }
  }

  return Promise.resolve(null);
}
