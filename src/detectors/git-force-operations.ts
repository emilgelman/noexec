import type { Detection, ToolUseData } from '../types';

/**
 * Detects dangerous git operations that can cause data loss or collaboration issues
 */

const GIT_DANGEROUS_PATTERNS = [
  // Force push (can overwrite remote history)
  /\bgit\s+push\s+[^\n]*--force(?!-with-lease\b)/,
  /\bgit\s+push\s+[^\n]*-f\s/,

  // Force push to main/master branches (extra dangerous)
  /\bgit\s+push\s+[^\n]*(?:--force|-f)\s+[^\n]*\b(?:main|master)\b/,

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
];

export function detectGitForceOperation(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  for (const pattern of GIT_DANGEROUS_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Dangerous git operation detected - can cause data loss or overwrite remote history',
        detector: 'git-force-operation',
      });
    }
  }

  return Promise.resolve(null);
}
