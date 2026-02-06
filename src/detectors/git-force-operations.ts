import type { Detection, ToolUseData } from '../types';

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

  // Branch deletion with force
  /\bgit\s+branch\s+[^\n]*-D\b/,

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
function isForceToProtectedBranch(command: string): boolean {
  const branch = extractPushBranch(command);
  if (!branch) return false;

  return PROTECTED_BRANCHES.some((protected_) => branch === protected_);
}

/**
 * Determine severity based on context
 */
function getSeverity(command: string): 'high' | 'medium' {
  // Force push to main/master/production is HIGH severity
  if (/\bgit\s+push.*--force/.test(command) && isForceToProtectedBranch(command)) {
    return 'high';
  }

  // Interactive rebase is medium (useful but risky)
  if (/\bgit\s+rebase\s+(?:-i|--interactive)/.test(command)) {
    return 'medium';
  }

  // Most other operations are high
  return 'high';
}

export function detectGitForceOperation(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  for (const pattern of GIT_DANGEROUS_PATTERNS) {
    if (pattern.test(toolInput)) {
      const severity = getSeverity(toolInput);

      return Promise.resolve({
        severity,
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
