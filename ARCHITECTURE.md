# noexec Architecture

**Version:** 0.1.0  
**Target Audience:** Developers contributing to noexec or building similar security tools for AI coding assistants

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Detector System](#detector-system)
5. [Extensibility](#extensibility)
6. [Testing Architecture](#testing-architecture)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Performance Considerations](#performance-considerations)

---

## System Overview

### What is noexec?

**noexec** is a runtime security tool that prevents AI coding assistants from accidentally executing dangerous commands or leaking sensitive credentials. It operates as a **pre-execution hook** in AI CLI tools, analyzing commands before they run on the user's system.

### Problem Statement

AI coding assistants like Claude Code, GitHub Copilot, and Cursor are powerful but can:

- **Accidentally expose secrets** (API keys, AWS credentials, SSH keys)
- **Run destructive commands** (`rm -rf /`, `dd if=/dev/zero`)
- **Perform risky git operations** (`git push --force origin main`)
- **Leak environment variables** (`echo $AWS_SECRET_ACCESS_KEY`)
- **Exfiltrate data** to external services unknowingly

Traditional security tools don't protect against these runtime risks in local development environments.

### Solution Approach

noexec uses a **hook-based security model** inspired by [Claude Code hooks](https://code.claude.com/docs/en/hooks):

```
┌─────────────────────────────────────────────────────────────┐
│  AI Coding Assistant (Claude Code, Copilot, etc.)          │
│  User prompt: "Deploy the app to production"                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  PreToolUse Hook      │  ← noexec registers here
         │  (Before execution)   │
         └──────────┬────────────┘
                    │
                    ▼
         ┌───────────────────────┐
         │  noexec analyze       │
         │  (Security analysis)  │
         └──────────┬────────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
         ▼                     ▼
    ┌─────────┐          ┌──────────┐
    │  Safe   │          │ Blocked  │
    │ Exit 0  │          │ Exit 2   │
    └────┬────┘          └─────┬────┘
         │                     │
         ▼                     ▼
    Execute             User notified
    command             of security risk
```

### MCP Ecosystem Integration

noexec integrates with the **Model Context Protocol (MCP)** ecosystem as a security layer:

- **MCP Server**: AI agents communicate via standardized protocol
- **Tool Execution**: MCP defines tool use structure (like Bash execution)
- **Hook System**: noexec intercepts via platform hooks (PreToolUse, etc.)
- **Fail-Safe Design**: Errors don't block legitimate work (fail-open)

### Key Design Principles

1. **Privacy-First**: All analysis runs locally, no network calls
2. **Zero Configuration**: Works out-of-the-box after `noexec init`
3. **Extensible**: Easy to add new detectors and platforms
4. **Fast**: Optimized regex patterns, <10ms analysis time
5. **Fail-Open**: Errors allow execution (don't break user workflow)

---

## Component Architecture

### High-Level Component Diagram

```mermaid
graph TB
    subgraph "User Space"
        CLI[noexec CLI<br/>src/cli.ts]
    end

    subgraph "Commands Layer"
        INIT[init Command<br/>src/commands/init.ts]
        ANALYZE[analyze Command<br/>src/commands/analyze.ts]
    end

    subgraph "Platform Integration"
        CLAUDE[Claude Config<br/>~/.claude/settings.json]
        STDIN[stdin: JSON ToolUseData]
    end

    subgraph "Detection Engine"
        DETECTORS[Detector Registry]
        CRED[Credential Leak<br/>Detector]
        DEST[Destructive Command<br/>Detector]
        GIT[Git Force Operation<br/>Detector]
        ENV[Env Var Leak<br/>Detector]
        MAGIC[Magic String<br/>Detector]
    end

    CLI -->|noexec init| INIT
    CLI -->|noexec analyze| ANALYZE
    INIT -->|Writes hook config| CLAUDE
    CLAUDE -->|Triggers on Bash execution| ANALYZE
    ANALYZE -->|Reads JSON from| STDIN
    ANALYZE -->|Runs all| DETECTORS
    DETECTORS --> CRED
    DETECTORS --> DEST
    DETECTORS --> GIT
    DETECTORS --> ENV
    DETECTORS --> MAGIC
    CRED -->|Detection/null| ANALYZE
    DEST -->|Detection/null| ANALYZE
    GIT -->|Detection/null| ANALYZE
    ENV -->|Detection/null| ANALYZE
    MAGIC -->|Detection/null| ANALYZE
    ANALYZE -->|Exit 0 = safe<br/>Exit 2 = blocked| CLI
```

### Component Breakdown

#### 1. CLI Entry Point (`src/cli.ts`)

**Responsibility**: Command-line interface and argument parsing

**Technology**: [Commander.js](https://github.com/tj/commander.js)

**Key Features**:

- Defines `init` and `analyze` commands
- Version information (`0.1.0`)
- Help text generation
- Command routing to handlers

**Code Structure**:

```typescript
#!/usr/bin/env node
import { Command } from 'commander';
import { initCommand } from './commands/init';
import { analyzeCommand } from './commands/analyze';

const program = new Command();
program.name('noexec').description('Security scanner for agentic CLIs').version('0.1.0');

program
  .command('init')
  .option('--platform <platform>', 'Specific platform', 'claude')
  .action(initCommand);

program
  .command('analyze')
  .option('--hook <hook>', 'Hook type', 'PreToolUse')
  .action(analyzeCommand);
```

**Exit Codes**:

- `0`: Success (safe command or init complete)
- `1`: Error (invalid arguments, parsing failure)
- `2`: Security issue detected (command blocked)

---

#### 2. Init Command (`src/commands/init.ts`)

**Responsibility**: Configure hooks in AI coding assistant platforms

**Supported Platforms**:

- ✅ Claude Code (via `~/.claude/settings.json`)
- 🔜 GitHub Copilot CLI (future)
- 🔜 Cursor (future)

**Claude Integration Details**:

The init command:

1. Locates `~/.claude/settings.json`
2. Creates directory if it doesn't exist
3. Reads existing configuration (preserves other settings)
4. Adds/updates PreToolUse hook for Bash matcher
5. Writes updated configuration

**Hook Configuration Example**:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "noexec analyze --hook PreToolUse"
          }
        ]
      }
    ]
  }
}
```

**Design Decisions**:

- **Idempotent**: Running `init` multiple times is safe
- **Preserves Existing Config**: Doesn't overwrite other hooks
- **User-Friendly Output**: Clear feedback on what was configured

---

#### 3. Analyze Command (`src/commands/analyze.ts`)

**Responsibility**: Security analysis of commands before execution

**Input**: JSON-formatted `ToolUseData` from stdin

**Process Flow**:

```mermaid
sequenceDiagram
    participant Hook as PreToolUse Hook
    participant Analyze as analyze Command
    participant Detectors as Detector Registry
    participant Detector as Individual Detector

    Hook->>Analyze: stdin: {"command": "rm -rf /"}
    Analyze->>Analyze: Parse JSON
    Analyze->>Detectors: Run all detectors
    loop For each detector
        Detectors->>Detector: detectXXX(toolUseData)
        Detector-->>Detectors: Detection | null
    end
    Detectors-->>Analyze: Detection[]
    alt Detections found
        Analyze->>Analyze: Log security warnings
        Analyze-->>Hook: exit(2) - BLOCKED
    else No detections
        Analyze-->>Hook: exit(0) - ALLOWED
    end
```

**Key Functions**:

```typescript
export async function analyzeStdin(input: string): Promise<Detection[]> {
  if (!input.trim()) return [];

  const toolUseData = JSON.parse(input) as ToolUseData;

  const detectors = [
    detectDestructiveCommand,
    detectGitForceOperation,
    detectCredentialLeak,
    detectEnvVarLeak,
    detectMagicString, // Test detector only
  ];

  const detections: Detection[] = [];

  for (const detector of detectors) {
    const result = await detector(toolUseData);
    if (result) {
      detections.push(result);
    }
  }

  return detections;
}
```

**Error Handling Philosophy**:

- **Fail-Open**: Errors don't block execution
- **Logged to stderr**: User sees warnings but work continues
- **Exit 0 on Error**: Prevents workflow disruption

**Output Format**:

```
⚠️  Security issues detected:

[HIGH] Potentially destructive command detected - could cause data loss
  Detector: destructive-command

[HIGH] Environment variable containing sensitive data detected
  Detector: env-var-leak
```

---

## Data Flow

### ToolUseData Structure

The core data structure passed from AI platforms to noexec:

```typescript
export interface ToolUseData {
  command?: string;
  [key: string]: unknown; // Extensible for platform-specific fields
}
```

**Example Data**:

```json
{
  "command": "curl -H 'Authorization: Bearer sk-abc123' https://api.example.com"
}
```

### Detection Result Structure

```typescript
export interface Detection {
  severity: 'high' | 'medium' | 'low';
  message: string;
  detector: string;
}
```

**Severity Guidelines**:

- **high**: Immediate data loss/credential exposure risk
- **medium**: Potentially dangerous but context-dependent
- **low**: Suspicious but likely safe (reserved for future use)

### Detector Function Signature

```typescript
export type Detector = (toolUseData: ToolUseData) => Promise<Detection | null>;
```

**Contract**:

- **Input**: `ToolUseData` object
- **Output**: `Detection` if issue found, `null` if safe
- **Async**: Allows for future async detectors (file I/O, API calls)
- **No Side Effects**: Detectors should be pure (except for logging)

### Complete Data Flow Example

```
┌──────────────────────────────────────────────────────────┐
│ 1. User in Claude Code                                   │
│    > "Delete the old database and deploy the new one"    │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 2. AI generates command                                  │
│    {"command": "rm -rf /var/db && git push --force"}    │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 3. PreToolUse hook intercepts (before execution)        │
│    Pipes JSON to: noexec analyze --hook PreToolUse      │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 4. analyzeStdin() parses JSON                            │
│    ToolUseData = {command: "rm -rf /var/db && ..."}     │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 5. Detector: detectDestructiveCommand()                 │
│    Pattern match: /\brm\s+.*-rf.*\/var/                 │
│    Result: {severity: 'high', message: '...', ...}      │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 6. Detector: detectGitForceOperation()                  │
│    Pattern match: /git push --force/                    │
│    Result: {severity: 'high', message: '...', ...}      │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 7. All detectors run (5 total in v0.1.0)                │
│    Detections: [Detection, Detection]  (2 issues found) │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 8. analyzeCommand() logs warnings to stderr             │
│    Exits with code 2 (blocked)                          │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ 9. PreToolUse hook receives exit code 2                 │
│    Claude Code blocks execution, shows warning to user  │
└──────────────────────────────────────────────────────────┘
```

---

## Detector System

### Detector Architecture

Each detector is a self-contained module that:

1. **Accepts** `ToolUseData` as input
2. **Analyzes** the command using pattern matching
3. **Returns** `Detection` or `null`
4. **Is stateless** (no global state, pure function)
5. **Is async** (for future extensibility)

### Current Detectors (v0.1.0)

#### 1. Credential Leak Detector

**File**: `src/detectors/credential-leak.ts`

**Purpose**: Detect exposed API keys, tokens, passwords, and credentials

**Detection Strategies**:

1. **Service-Specific Patterns** (High Confidence)
   - GitHub: `ghp_*`, `gho_*`, `github_pat_*`
   - AWS: `AKIA*` format
   - Stripe: `sk_live_*`, `sk_test_*`
   - OpenAI/Anthropic: `sk-*`, `sk-ant-*`
   - Slack: `xox[baprs]-*`
   - Twilio: `AC*`, `SK*`
   - SendGrid: `SG.*`
   - SSH Keys: `-----BEGIN PRIVATE KEY-----`
   - Google: `AIza*`
   - npm: `npm_*`
   - PyPI: `pypi-*`

2. **Generic Patterns** (With Context Checks)
   - `api_key=...`, `password=...`, `secret=...`
   - **Entropy Analysis**: Reject low-randomness strings
   - **Placeholder Detection**: Skip "example", "test", "xxx", etc.

**Key Functions**:

```typescript
function calculateEntropy(str: string): number {
  // Shannon entropy calculation
  // High entropy = random = likely real credential
}

function isPlaceholder(str: string): boolean {
  // Check against common placeholder patterns
  // e.g., "example_key", "your-token-here", "xxx"
}

function hasSufficientEntropy(value: string, minEntropy = 3.0): boolean {
  // Minimum length of 8 characters
  // Entropy threshold of 3.0 bits
}
```

**Examples**:

✅ **Detected**:

```bash
echo $AWS_SECRET_ACCESS_KEY
curl -H "Authorization: Bearer ghp_1234567890abcdef1234567890abcdef12345678"
cat ~/.ssh/id_rsa
export STRIPE_SECRET_KEY=sk_live_EXAMPLE_FAKE_KEY_DO_NOT_USE
```

❌ **Not Detected** (False Positive Prevention):

```bash
export API_KEY="example_key_here"
password=test
api_key="replace-with-your-key"
```

---

#### 2. Destructive Command Detector

**File**: `src/detectors/destructive-commands.ts`

**Purpose**: Prevent data loss, system damage, and denial-of-service

**Patterns Detected**:

1. **File Deletion**
   - `rm -rf /`, `rm -rf ~`, `rm -rf /*`
   - Safe path whitelist: `./node_modules`, `./dist`, `/tmp`, etc.

2. **Disk Operations**
   - `dd if=/dev/zero` (disk filling)
   - `mkfs` (format filesystem)
   - `fdisk`, `parted` (partition editing)

3. **Process Attacks**
   - Fork bombs: `:(){ :|:& };:`
   - Mass killers: `kill -9 -1`, `pkill -9 -U`

4. **Network Disruption**
   - `iptables -F` (flush firewall)
   - `ip link set eth0 down`

5. **System Files**
   - `> /etc/passwd`, `> /boot/`
   - `chmod 000 /bin/bash`

**Safe Path Detection**:

```typescript
const SAFE_PATHS = [
  /^\.\/node_modules/,
  /^\.\/dist/,
  /^\.\/build/,
  /^\.?\/?tmp\//,
  // ... more patterns
];

function isSafePath(path: string): boolean {
  for (const safePattern of SAFE_PATHS) {
    if (safePattern.test(path)) {
      return true;
    }
  }
  return false;
}
```

**Example Safe vs Unsafe**:

✅ **Allowed** (safe paths):

```bash
rm -rf ./node_modules
rm -rf /tmp/build-1234
rm -rf ./dist
```

❌ **Blocked** (dangerous):

```bash
rm -rf /
rm -rf /var/www
dd if=/dev/zero of=/dev/sda
```

---

#### 3. Git Force Operations Detector

**File**: `src/detectors/git-force-operations.ts`

**Purpose**: Prevent accidental history rewriting and data loss in Git

**Patterns Detected**:

1. **Force Push** (excluding safer variants)
   - ❌ `git push --force`
   - ❌ `git push -f`
   - ✅ `git push --force-with-lease` (allowed - safer)

2. **History Rewriting**
   - `git reset --hard`
   - `git filter-branch`
   - `git rebase -i` (interactive rebase)

3. **Destructive Cleanup**
   - `git clean -f` (removes untracked files)
   - `git branch -D` (force delete)
   - `git reflog expire`

**Context-Aware Severity**:

```typescript
function getSeverity(command: string): 'high' | 'medium' {
  // Force push to protected branch = HIGH
  if (/git push.*--force/.test(command) && isForceToProtectedBranch(command)) {
    return 'high';
  }

  // Interactive rebase = MEDIUM (useful but risky)
  if (/git rebase -i/.test(command)) {
    return 'medium';
  }

  return 'high';
}
```

**Protected Branches** (customizable):

```typescript
const PROTECTED_BRANCHES = ['main', 'master', 'production', 'prod', 'release'];
```

**Future Enhancement**: Config file support for custom protected branches

---

#### 4. Environment Variable Leak Detector

**File**: `src/detectors/env-var-leak.ts`

**Purpose**: Prevent sensitive environment variables from being exposed

**Sensitive Variable Patterns**:

- AWS: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- GCP: `GOOGLE_APPLICATION_CREDENTIALS`, `GCP_PROJECT`
- Azure: `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- Generic: `API_KEY`, `SECRET_KEY`, `PASSWORD`, `TOKEN`
- Databases: `DATABASE_URL`, `POSTGRES_PASSWORD`, `MONGODB_URI`
- Services: `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`

**Dangerous Contexts**:

1. **Direct Output**: `echo $SECRET_KEY`
2. **Network Requests**: `curl -d "secret=$API_KEY"`
3. **Logging**: `$PASSWORD >> log.txt`
4. **Git Commits**: `git commit -m "$SECRET"`

**Indirect Exposure Detection**:

```typescript
const INDIRECT_DUMP_PATTERNS = [
  /\b(?:env|printenv|export)\s*(?:\||$)/, // env | grep
  /\bset\s*(?:\||$)/, // set | grep
  /\bcat\s+[^\n]*\.env/, // cat .env
  /\bcp\s+[^\n]*\.env/, // cp .env backup.env
];
```

**Safe Context Detection**:

```bash
# Not flagged (safe):
if [ -z "$API_KEY" ]; then ...      # Conditional check
myapp --api-key "$API_KEY"          # App consumption

# Flagged (unsafe):
echo "Key is: $API_KEY"             # Exposure to stdout
curl https://api.com -d "$SECRET"   # Network exposure
```

**Severity Levels**:

- **High**: Direct exposure (`echo $SECRET`, `curl -d "$KEY"`)
- **Medium**: Reference without obvious exposure context

---

#### 5. Magic String Detector (Test/Example Only)

**File**: `src/detectors/magic-string.ts`

**Purpose**: Demonstration detector for testing and documentation

**Pattern**: Detects hardcoded string `"test_me"`

**Status**: Should be removed before v1.0.0 or clearly marked as example

---

### Detector Registration

**Location**: `src/commands/analyze.ts`

```typescript
const detectors = [
  detectDestructiveCommand, // Priority: High risk first
  detectGitForceOperation,
  detectCredentialLeak,
  detectEnvVarLeak,
  detectMagicString, // Test only
];
```

**Execution Order**: Sequential (could be parallelized in future)

**Short-Circuit**: None - all detectors run to find multiple issues

---

### Async Pattern Justification

All detectors return `Promise<Detection | null>` even though current implementations are synchronous:

**Reasons**:

1. **Future-Proofing**: File I/O checks, API rate limits, ML models
2. **Consistency**: Uniform interface across detectors
3. **Testability**: Easier to mock async operations
4. **Extensibility**: Plugin system can support async detectors

**Example Future Async Detector**:

```typescript
async function detectMaliciousDomain(toolUseData: ToolUseData): Promise<Detection | null> {
  const domains = extractDomains(toolUseData.command);

  // Check against local threat intel database
  for (const domain of domains) {
    const isMalicious = await threatDB.lookup(domain);
    if (isMalicious) {
      return {
        severity: 'high',
        message: `Malicious domain detected: ${domain}`,
        detector: 'malicious-domain',
      };
    }
  }

  return null;
}
```

---

## Extensibility

### Adding a New Detector

**Step 1**: Create detector file

```bash
touch src/detectors/my-new-detector.ts
```

**Step 2**: Implement detector interface

```typescript
// src/detectors/my-new-detector.ts
import type { Detection, ToolUseData } from '../types';

export async function detectMyNewIssue(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Your detection logic
  const patterns = [/dangerous-pattern/, /another-pattern/];

  for (const pattern of patterns) {
    if (pattern.test(toolInput)) {
      return {
        severity: 'high', // or 'medium' or 'low'
        message: 'Clear, actionable description of the security issue',
        detector: 'my-new-detector',
      };
    }
  }

  return null;
}
```

**Step 3**: Register detector

```typescript
// src/commands/analyze.ts
import { detectMyNewIssue } from '../detectors/my-new-detector';

const detectors = [
  detectDestructiveCommand,
  detectGitForceOperation,
  detectCredentialLeak,
  detectEnvVarLeak,
  detectMyNewIssue, // Add here
];
```

**Step 4**: Write tests

```typescript
// src/detectors/__tests__/my-new-detector.test.ts
import { describe, it, expect } from 'vitest';
import { detectMyNewIssue } from '../my-new-detector';

describe('detectMyNewIssue', () => {
  it('should detect dangerous pattern', async () => {
    const toolData = { command: 'dangerous-command' };
    const result = await detectMyNewIssue(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
    expect(result?.detector).toBe('my-new-detector');
  });

  it('should not flag safe commands', async () => {
    const toolData = { command: 'safe-command' };
    const result = await detectMyNewIssue(toolData);

    expect(result).toBeNull();
  });
});
```

**Step 5**: Run tests

```bash
npm test
npm run test:coverage
```

---

### Best Practices for Detector Development

#### 1. False Positive Reduction

**Problem**: Blocking legitimate commands frustrates users

**Solutions**:

- **Entropy Analysis**: Check randomness of credentials
- **Placeholder Detection**: Skip "example", "test", "xxx"
- **Safe Path Whitelists**: Allow `./node_modules`, `/tmp`
- **Context Awareness**: `git push --force feature/*` vs `main`

**Example**:

```typescript
// Bad: Too aggressive
if (/password/.test(command)) {
  return detection;
}

// Good: Context-aware
if (/password=([a-zA-Z0-9]{20,})/.test(command)) {
  const value = match[1];
  if (hasSufficientEntropy(value) && !isPlaceholder(value)) {
    return detection;
  }
}
```

#### 2. Performance Optimization

**Goal**: <10ms analysis time per command

**Techniques**:

- **Compiled Regex**: Declare patterns at module level
- **Early Returns**: Short-circuit on first match
- **String Conversion Once**: `JSON.stringify(toolUseData)` once
- **Avoid Backtracking**: Carefully craft regex patterns

**Example**:

```typescript
// Bad: Recompile regex every call
function detect(data: ToolUseData): Detection | null {
  const pattern = new RegExp('something'); // ❌ Slow
  if (pattern.test(JSON.stringify(data))) {
    return detection;
  }
}

// Good: Precompile at module level
const PATTERN = /something/; // ✅ Fast
function detect(data: ToolUseData): Detection | null {
  if (PATTERN.test(JSON.stringify(data))) {
    return detection;
  }
}
```

#### 3. Clear Error Messages

**Goal**: User understands why command was blocked

**Guidelines**:

- **Be specific**: "AWS credentials detected" not "secret found"
- **Actionable**: Suggest alternatives where possible
- **No jargon**: Assume user is not security expert

**Example**:

```typescript
// Bad: Vague
message: 'Security issue detected';

// Good: Specific and actionable
message: 'GitHub personal access token detected in command - avoid exposing tokens in logs or network requests';
```

#### 4. Severity Calibration

**Severity Levels**:

- **high**: Immediate risk (credential exposure, data loss)
- **medium**: Context-dependent risk (interactive rebase, env var reference)
- **low**: Suspicious but likely safe (reserved for future use)

**Example**:

```typescript
// Context-aware severity
function getSeverity(command: string, branch: string): Severity {
  if (branch === 'main' || branch === 'master') {
    return 'high'; // Force push to main = high risk
  } else if (branch.startsWith('feature/')) {
    return 'medium'; // Force push to feature branch = medium risk
  }
  return 'high';
}
```

---

### Future Plugin System (v1.0.0+)

**Design Goals**:

- **Third-party detectors**: Community contributions without core changes
- **Configuration**: Enable/disable detectors via config file
- **Priority/ordering**: Control detector execution order
- **Custom rules**: User-specific patterns

**Proposed Structure**:

```typescript
// noexec.config.json
{
  "detectors": {
    "credential-leak": { "enabled": true, "priority": 1 },
    "destructive-command": { "enabled": true, "priority": 2 },
    "custom-detector": {
      "enabled": true,
      "priority": 10,
      "plugin": "./plugins/my-detector.js"
    }
  },
  "whitelist": {
    "commands": ["rm -rf ./node_modules"],
    "patterns": ["^npm ci$"]
  }
}
```

**Plugin Interface**:

```typescript
// ./plugins/my-detector.js
module.exports = {
  name: 'my-custom-detector',
  version: '1.0.0',
  detect: async (toolUseData) => {
    // Custom detection logic
    if (/* issue found */) {
      return {
        severity: 'high',
        message: 'Custom issue detected',
        detector: 'my-custom-detector',
      };
    }
    return null;
  },
};
```

---

### Adding Platform Support

**Current**: Claude Code only  
**Future**: GitHub Copilot CLI, Cursor, Continue.dev

**Requirements**:

1. **Hook mechanism**: Pre-execution interception
2. **JSON input**: Structured command data
3. **Exit code handling**: Platform respects `exit 2` = block

**Example: Adding GitHub Copilot Support**

```typescript
// src/commands/init.ts

async function initGitHubCopilot(): Promise<void> {
  const configPath = path.join(os.homedir(), '.copilot/config.json');

  let config = readConfigOrDefault(configPath);

  config.hooks = config.hooks || {};
  config.hooks.preExecute = config.hooks.preExecute || [];
  config.hooks.preExecute.push({
    command: 'noexec analyze --hook PreExecute',
    matchers: ['shell', 'bash'],
  });

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log('GitHub Copilot CLI configured!');
}

// Update initCommand() to support new platform
export async function initCommand(options: InitOptions): Promise<void> {
  switch (options.platform) {
    case 'claude':
      await initClaude();
      break;
    case 'copilot':
      await initGitHubCopilot();
      break;
    default:
      console.error(`Unknown platform: ${options.platform}`);
      process.exit(1);
  }
}
```

---

## Testing Architecture

### Testing Layers

```
┌─────────────────────────────────────────┐
│  Integration Tests                      │  ← End-to-end CLI testing
│  test/integration/*.test.ts             │
├─────────────────────────────────────────┤
│  Unit Tests (Commands)                  │  ← Command logic testing
│  src/commands/__tests__/*.test.ts       │
├─────────────────────────────────────────┤
│  Unit Tests (Detectors)                 │  ← Detector pattern testing
│  src/detectors/__tests__/*.test.ts      │
└─────────────────────────────────────────┘
```

### Testing Framework

**Technology**: [Vitest](https://vitest.dev/) - Fast, modern test runner

**Why Vitest?**

- ⚡ **Fast**: Vite-powered, instant re-runs
- 🔧 **ESM support**: Native ES modules (TypeScript)
- 📊 **Built-in coverage**: v8 provider
- 🎨 **UI mode**: Visual test explorer (`npm run test:ui`)
- 🧪 **Compatible**: Jest-like API (easy migration)

**Configuration**: `vitest.config.ts`

```typescript
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000, // Integration tests need more time
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 95,
        statements: 85,
      },
    },
  },
});
```

---

### 1. Integration Tests

**Location**: `test/integration/`

**Purpose**: Test full CLI workflows (init, analyze)

**Key Tests**:

#### CLI Init Tests (`cli-init.test.ts`)

- ✅ Creates Claude config from scratch
- ✅ Updates existing config without overwriting
- ✅ Idempotent (multiple runs are safe)
- ✅ Preserves other hooks

#### CLI Analyze Tests (`cli-analyze.test.ts`)

- ✅ Blocks dangerous commands (exit code 2)
- ✅ Allows safe commands (exit code 0)
- ✅ Handles invalid JSON input
- ✅ Multiple detections in single command

**Example Integration Test**:

```typescript
import { describe, it, expect } from 'vitest';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

describe('CLI Integration: analyze command', () => {
  it('should block destructive command', async () => {
    const input = JSON.stringify({ command: 'rm -rf /' });

    try {
      await execAsync(`echo '${input}' | node dist/cli.js analyze`);
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error.code).toBe(2); // Blocked
      expect(error.stderr).toContain('destructive-command');
    }
  });

  it('should allow safe command', async () => {
    const input = JSON.stringify({ command: 'ls -la' });

    const { stdout, stderr } = await execAsync(`echo '${input}' | node dist/cli.js analyze`);

    expect(stderr).toBe(''); // No warnings
  });
});
```

#### Performance Tests (`performance.test.ts`)

- ✅ Analysis completes <100ms (target: <10ms)
- ✅ Scales linearly with detector count
- ✅ Memory usage stays reasonable

---

### 2. Unit Tests: Commands

**Location**: `src/commands/__tests__/`

**Purpose**: Test command logic in isolation

#### Analyze Command Tests (`analyze.test.ts`)

**Coverage**:

- ✅ Empty input handling
- ✅ Invalid JSON parsing
- ✅ Single detector triggers
- ✅ Multiple detections aggregation
- ✅ Safe commands pass through

**Example**:

```typescript
describe('analyzeStdin', () => {
  it('should return empty array for safe command', async () => {
    const input = JSON.stringify({ command: 'ls -la' });
    const detections = await analyzeStdin(input);
    expect(detections).toEqual([]);
  });

  it('should return multiple detections for compound issue', async () => {
    const input = JSON.stringify({
      command: 'rm -rf / && echo $AWS_SECRET_KEY && git push --force',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThanOrEqual(3);

    const detectorNames = detections.map((d) => d.detector);
    expect(detectorNames).toContain('destructive-command');
    expect(detectorNames).toContain('env-var-leak');
    expect(detectorNames).toContain('git-force-operation');
  });
});
```

#### Init Command Tests (`init.test.ts`)

**Coverage**:

- ✅ Creates new config file
- ✅ Updates existing config
- ✅ Preserves other hooks
- ✅ Idempotent operations

---

### 3. Unit Tests: Detectors

**Location**: `src/detectors/__tests__/`

**Purpose**: Comprehensive pattern testing for each detector

**Test Structure** (85+ test cases total):

Each detector test suite includes:

- **Positive tests**: Dangerous patterns correctly detected
- **Negative tests**: Safe commands not flagged (false positives)
- **Edge cases**: Boundary conditions, special characters
- **Service-specific**: Platform-specific token formats

#### Example: Credential Leak Tests

```typescript
describe('detectCredentialLeak', () => {
  // Positive tests
  it('should detect AWS access keys', async () => {
    const result = await detectCredentialLeak({
      command: 'echo AKIAIOSFODNN7EXAMPLE',
    });
    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });

  it('should detect GitHub tokens', async () => {
    const result = await detectCredentialLeak({
      command: 'curl -H "token: ghp_1234567890123456789012345678901234567890"',
    });
    expect(result).not.toBeNull();
  });

  // Negative tests (false positive prevention)
  it('should not detect placeholders', async () => {
    const result = await detectCredentialLeak({
      command: 'export API_KEY="example_key_here"',
    });
    expect(result).toBeNull();
  });

  it('should not detect low-entropy strings', async () => {
    const result = await detectCredentialLeak({
      command: 'password=test123',
    });
    expect(result).toBeNull();
  });

  // Edge cases
  it('should detect credentials in complex commands', async () => {
    const result = await detectCredentialLeak({
      command: 'curl -d "key=sk-abc123def456" https://api.example.com | jq',
    });
    expect(result).not.toBeNull();
  });
});
```

#### Test Coverage Statistics (v0.1.0)

**Overall Coverage**:

- Lines: **>85%**
- Functions: **>85%**
- Branches: **>95%**
- Statements: **>85%**

**Excluded from Coverage**:

- CLI entry point (`src/cli.ts`) - tested via integration tests
- Type definitions (`src/types.ts`)
- Test files themselves
- Config files (`vitest.config.ts`, `eslint.config.js`)

**Detector-Specific Coverage**:

| Detector            | Test Cases | Coverage |
| ------------------- | ---------- | -------- |
| Credential Leak     | 25+        | 100%     |
| Destructive Command | 20+        | 100%     |
| Git Force Operation | 15+        | 100%     |
| Env Var Leak        | 20+        | 100%     |
| Magic String (test) | 5+         | 100%     |

---

### Running Tests

```bash
# Run all tests (unit + integration)
npm test

# Watch mode (auto-rerun on changes)
npm run test:watch

# Visual UI mode
npm run test:ui

# Generate coverage report
npm run test:coverage

# Coverage report location: ./coverage/index.html
```

---

### Test-Driven Development (TDD) Workflow

**When adding a new detector**:

1. **Write failing tests first**:

```bash
touch src/detectors/__tests__/new-detector.test.ts
# Write test cases
npm test  # Should fail
```

2. **Implement detector**:

```bash
touch src/detectors/new-detector.ts
# Implement detection logic
npm test  # Should pass
```

3. **Verify coverage**:

```bash
npm run test:coverage
# Check that new detector has >85% coverage
```

4. **Add integration test**:

```typescript
// test/integration/cli-analyze.test.ts
it('should detect new issue type', async () => {
  const input = JSON.stringify({ command: 'dangerous-new-pattern' });
  // ... test full CLI flow
});
```

---

## CI/CD Pipeline

### GitHub Actions Workflows

**Location**: `.github/workflows/`

### 1. CI Pipeline (`ci.yml`)

**Triggers**:

- Push to `main` branch
- Pull requests to `main`

**Matrix Strategy**: Multi-OS, Multi-Node

```yaml
strategy:
  fail-fast: false
  matrix:
    node-version: [18, 20, 22]
    os: [ubuntu-latest, macos-latest]
```

**Total Combinations**: 6 (3 Node versions × 2 OSes)

**Why This Matrix?**

- **Node 18**: Minimum supported (LTS)
- **Node 20**: Current LTS
- **Node 22**: Latest stable
- **Ubuntu**: Primary Linux target
- **macOS**: Developer workstation compatibility
- **Windows**: Not yet tested (future addition)

**Pipeline Steps**:

```mermaid
graph LR
    A[Checkout Code] --> B[Setup Node]
    B --> C[Install Dependencies]
    C --> D[Run Linting]
    D --> E[Build TypeScript]
    E --> F[Run Tests]
    F --> G[Generate Coverage]
    G --> H[Upload to Codecov]
```

**Detailed Steps**:

1. **Checkout**: `actions/checkout@v4`
2. **Node Setup**: `actions/setup-node@v4` with npm cache
3. **Dependencies**: `npm ci` (clean install from lock file)
4. **Linting**: `npm run lint` (ESLint + Prettier)
5. **Build**: `npm run build` (TypeScript compilation)
6. **Tests**: `npm test` (Vitest unit + integration)
7. **Coverage**: `npm run test:coverage` (Ubuntu + Node 22 only)
8. **Upload**: Codecov for coverage tracking

**Exit Criteria**:

- All steps must pass on all matrix combinations
- No linting errors
- All tests pass
- Coverage thresholds met (85%+ lines, 95%+ branches)

---

### 2. Security Audit Pipeline (`security.yml`)

**Triggers**:

- Push to `main` branch
- Pull requests to `main`
- **Weekly schedule**: Monday 00:00 UTC (cron: `0 0 * * 1`)

**Purpose**: Continuous security monitoring

**Steps**:

```mermaid
graph TB
    A[Checkout Code] --> B[Setup Node 22]
    B --> C[npm ci]
    C --> D[npm audit]
    C --> E[npm outdated]
    C --> F[CodeQL Init]
    F --> G[CodeQL Analysis]
```

**Security Checks**:

1. **npm audit**: Detects known vulnerabilities in dependencies
   - Threshold: `--audit-level=moderate`
   - Blocks PR if moderate/high/critical vulnerabilities found

2. **npm outdated**: Checks for outdated dependencies
   - Informational only (doesn't block)
   - Helps maintainers stay current

3. **CodeQL Analysis**: GitHub's semantic code analysis
   - Language: `javascript-typescript`
   - Detects: SQL injection, XSS, code injection, etc.
   - Scans: Custom code (not dependencies)

**Weekly Schedule Rationale**:

- New CVEs published daily
- Catch dependency vulnerabilities early
- Don't rely on manual checks

---

### Dependency Management

**Lock File**: `package-lock.json` committed to repo

**Why?**

- Reproducible builds across environments
- Consistent versions in CI/CD
- Faster `npm ci` (vs `npm install`)

**Update Process**:

```bash
# Security updates only
npm audit fix

# Major version updates (manual review)
npm outdated
npm install <package>@latest

# Regenerate lock file
npm install
```

---

### Pre-Commit Hooks (Husky + lint-staged)

**Technology**: [Husky](https://typicode.github.io/husky/) + [lint-staged](https://github.com/okonet/lint-staged)

**Configuration**:

```json
// package.json
{
  "lint-staged": {
    "*.{ts,js}": ["eslint --fix", "prettier --write"],
    "*.{json,md}": ["prettier --write"]
  }
}
```

**Pre-Commit Flow**:

```
git commit
  ↓
Husky intercepts
  ↓
lint-staged runs
  ↓
Format staged *.ts, *.js files (ESLint + Prettier)
  ↓
Format staged *.json, *.md files (Prettier)
  ↓
If fixes applied: Restage files
  ↓
Commit proceeds
```

**Benefits**:

- ✅ Consistent code style across contributors
- ✅ Catch linting errors before CI
- ✅ No manual formatting needed
- ✅ Smaller, cleaner commits

---

### Release Process (Future v0.2.0+)

**Proposed Workflow**:

1. **Version Bump**: `npm version patch|minor|major`
2. **Changelog Update**: Auto-generate from commit messages
3. **Build**: `npm run build`
4. **Test**: Full test suite + manual smoke tests
5. **Publish**: `npm publish`
6. **Tag**: `git tag v0.2.0 && git push --tags`
7. **GitHub Release**: Auto-create with changelog

**Semantic Versioning** (SemVer):

- **Patch** (0.1.x): Bug fixes, performance improvements
- **Minor** (0.x.0): New detectors, features (backward-compatible)
- **Major** (x.0.0): Breaking changes (API, config format)

---

## Performance Considerations

### Performance Goals

- **Analysis Time**: <10ms per command (target <5ms)
- **Memory**: <50MB RSS (resident set size)
- **Startup Time**: <100ms (cold start)
- **Scalability**: Linear with detector count

### Current Performance (v0.1.0)

**Benchmark Results** (on typical developer machine):

| Operation               | Time   |
| ----------------------- | ------ |
| Single detector (regex) | ~0.5ms |
| All 5 detectors         | ~3ms   |
| JSON parse              | ~0.1ms |
| CLI startup (node)      | ~50ms  |
| Total end-to-end        | ~60ms  |

**Bottlenecks**:

- Node.js startup dominates (50ms)
- Actual analysis is negligible (<5ms)
- I/O (stdin read) ~5-10ms

### Optimization Techniques

#### 1. Compiled Regex Patterns

**Bad** (slow):

```typescript
function detect(input: string): boolean {
  return new RegExp('pattern').test(input); // Recompile every call
}
```

**Good** (fast):

```typescript
const PATTERN = /pattern/; // Compile once at module load
function detect(input: string): boolean {
  return PATTERN.test(input);
}
```

**Impact**: ~10x faster for repeated calls

---

#### 2. Early Returns

**Optimization**: Stop on first detection (for blocking)

```typescript
// Current: Run all detectors (find multiple issues)
for (const detector of detectors) {
  const result = await detector(toolUseData);
  if (result) {
    detections.push(result); // Continue to find all issues
  }
}

// Future option: Stop on first detection (faster)
for (const detector of detectors) {
  const result = await detector(toolUseData);
  if (result) {
    return [result]; // Short-circuit
  }
}
```

**Trade-off**: Faster but user sees only one issue at a time

---

#### 3. String Conversion Once

```typescript
// Bad: Convert to string multiple times
function detect1(data: ToolUseData): Detection | null {
  if (/pattern1/.test(JSON.stringify(data))) { ... }
}

function detect2(data: ToolUseData): Detection | null {
  if (/pattern2/.test(JSON.stringify(data))) { ... }
}

// Good: Convert once, pass string
function analyzeStdin(input: string): Detection[] {
  const toolUseData = JSON.parse(input);
  const toolInput = JSON.stringify(toolUseData);  // Once

  for (const detector of detectors) {
    await detector(toolUseData);  // Each detector stringifies internally
  }
}

// Better: Pass both object and string
function detect(data: ToolUseData, dataStr: string): Detection | null {
  if (/pattern/.test(dataStr)) { ... }  // Use pre-stringified version
}
```

---

#### 4. Regex Optimization

**Guidelines**:

- Avoid catastrophic backtracking: `(a+)+b` is dangerous
- Use atomic groups where possible: `(?:...)` vs `(...)`
- Prefer character classes: `[a-zA-Z]` vs `(?:[a-z]|[A-Z])`
- Anchor patterns: `^` and `$` to limit search space

**Example**:

```typescript
// Bad: Potential backtracking
const BAD_PATTERN = /(\w+)+@/;

// Good: No backtracking
const GOOD_PATTERN = /\w+@/;
```

---

#### 5. Lazy Loading (Future)

**Idea**: Load detectors only when needed

```typescript
// Current: All detectors loaded at startup
import { detectCredentialLeak } from './detectors/credential-leak';
import { detectDestructiveCommand } from './detectors/destructive-commands';
// ...

// Future: Dynamic import based on config
const enabledDetectors = config.detectors.filter((d) => d.enabled);
for (const detectorConfig of enabledDetectors) {
  const detector = await import(`./detectors/${detectorConfig.name}`);
  // ...
}
```

**Benefit**: Faster startup if only subset of detectors enabled

---

### Memory Management

**Current Memory Profile**:

- Base Node.js process: ~20MB
- Loaded modules: ~10MB
- Runtime (analysis): ~5MB
- **Total**: ~35MB RSS

**No Memory Leaks**: Detectors are stateless (pure functions)

---

### Scalability Analysis

**Horizontal Scaling**: N detectors = O(N) time

**Example** (5 detectors × 0.5ms each):

- 5 detectors: ~3ms
- 10 detectors: ~6ms
- 20 detectors: ~12ms

**Still within <100ms budget**

---

### Future Performance Improvements

#### 1. Parallel Detector Execution

```typescript
// Current: Sequential
for (const detector of detectors) {
  const result = await detector(toolUseData);
  if (result) detections.push(result);
}

// Future: Parallel
const results = await Promise.all(detectors.map((detector) => detector(toolUseData)));
const detections = results.filter((r) => r !== null);
```

**Impact**: ~5x faster (if detectors are truly independent)

**Challenge**: Error handling in parallel execution

---

#### 2. Caching (for repeated commands)

```typescript
const cache = new Map<string, Detection[]>();

function analyzeWithCache(toolInput: string): Detection[] {
  if (cache.has(toolInput)) {
    return cache.get(toolInput)!;
  }

  const detections = runAllDetectors(toolInput);
  cache.set(toolInput, detections);
  return detections;
}
```

**Use Case**: AI retries same command multiple times

**Trade-off**: Memory usage vs speed

---

#### 3. JIT Compilation (Native Module)

**Idea**: Compile hot-path regex to native code (Rust, Go)

**Example**:

```typescript
// Current: JavaScript regex
const pattern = /AKIA[A-Z0-9]{16}/;

// Future: Native binding
const { detectAWSKey } = require('./native/detector.node');
```

**Impact**: ~10-100x faster for complex patterns

**Trade-off**: Build complexity, cross-platform support

---

## Conclusion

noexec is a **modular, extensible, and performant** security tool for AI coding assistants. Its architecture prioritizes:

1. **Simplicity**: Easy to understand and contribute to
2. **Extensibility**: Add detectors without touching core
3. **Performance**: <10ms analysis, negligible overhead
4. **Reliability**: 85%+ test coverage, fail-open design
5. **Privacy**: 100% local, no telemetry

### Key Architectural Decisions

| Decision        | Rationale                                       |
| --------------- | ----------------------------------------------- |
| TypeScript      | Type safety, better DX, ecosystem compatibility |
| Commander.js    | Standard CLI framework, well-documented         |
| Vitest          | Fast, modern, ESM-native testing                |
| Async detectors | Future-proofing for I/O, ML models              |
| Regex-based     | Fast, transparent, auditable                    |
| Fail-open       | User experience > security theater              |
| Hook-based      | Non-invasive, platform-agnostic                 |

### Future Roadmap

**v0.2.0**: More detectors, better test coverage  
**v0.3.0**: Configuration file, whitelist/blacklist  
**v1.0.0**: Stable API, plugin system, multi-platform

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas needing help**:

- 🔍 New detectors (database, Docker, network)
- 🔌 Platform integrations (Copilot, Cursor)
- 📊 Performance benchmarks
- 📚 Documentation improvements

---

**Last Updated**: 2026-02-06  
**Authors**: Emil Gelman and contributors  
**License**: MIT
