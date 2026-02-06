# Troubleshooting Guide

This guide helps you diagnose and resolve issues with noexec. If you can't find a solution here, please [open an issue on GitHub](https://github.com/emilgelman/noexec/issues).

## Table of Contents

- [Installation Issues](#installation-issues)
- [Detection Issues](#detection-issues)
- [Debugging](#debugging)
- [Common Questions](#common-questions)
- [Reporting Issues](#reporting-issues)

---

## Installation Issues

### npm install failures

#### Problem: "permission denied" errors

```bash
npm ERR! Error: EACCES: permission denied
```

**Solution:**

Use the `-g` flag with `npm install` (recommended):

```bash
npm install -g noexec
```

If you still see permission errors, use one of these approaches:

**Option 1: Use npx (no global install needed)**

```bash
npx noexec init
```

**Option 2: Fix npm permissions** (recommended by npm)

```bash
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
npm install -g noexec
```

**Option 3: Use sudo** (not recommended)

```bash
sudo npm install -g noexec
```

#### Problem: "Cannot find module" after install

```bash
Error: Cannot find module '/usr/local/lib/node_modules/noexec/dist/cli.js'
```

**Solution:**

1. Rebuild the package:

   ```bash
   npm install -g noexec
   ```

2. Verify the installation:

   ```bash
   which noexec
   noexec --version
   ```

3. If still broken, reinstall:
   ```bash
   npm uninstall -g noexec
   npm cache clean --force
   npm install -g noexec
   ```

### Node version mismatches

#### Problem: "engine" compatibility errors

```bash
npm ERR! engine Unsupported engine
npm ERR! engine Not compatible with your version of node/npm
```

**Solution:**

noexec requires **Node.js >= 18.0.0**. Check your version:

```bash
node --version
```

If you have an older version:

**Using nvm (recommended):**

```bash
nvm install 18
nvm use 18
npm install -g noexec
```

**Using system package manager:**

```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS (Homebrew)
brew install node@18
brew link node@18

# Then install noexec
npm install -g noexec
```

### Claude Code MCP setup problems

#### Problem: Hook not working after `noexec init`

**Symptoms:**

- Commands that should be blocked are executing
- No security warnings appear
- Claude Code doesn't seem to call noexec

**Diagnosis:**

1. Check if the hook was installed:

   ```bash
   cat ~/.claude/settings.json
   ```

   You should see:

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

2. Verify noexec is in your PATH:
   ```bash
   which noexec
   ```

**Solution:**

If the hook is missing or incorrect:

```bash
# Re-run init
noexec init --platform claude

# If that fails, manually edit ~/.claude/settings.json
# Add the hook configuration shown above
```

If noexec isn't in PATH:

```bash
# Find where it's installed
npm list -g noexec

# Add to your PATH (e.g., in ~/.bashrc)
export PATH="/path/to/npm/bin:$PATH"
```

#### Problem: "Unknown platform" error

```bash
Error: Platform 'claude' not found
```

**Solution:**

Make sure you're running the latest version:

```bash
npm install -g noexec@latest
noexec init --platform claude
```

If Claude Code is installed in a non-standard location, manually specify the config path in `~/.claude/settings.json`.

#### Problem: Hook runs but always exits with code 0

**Symptoms:**

- Dangerous commands execute despite noexec being configured
- No error messages in Claude Code output

**Diagnosis:**

Test the analyze command directly:

```bash
echo '{"command": "rm -rf /"}' | noexec analyze --hook PreToolUse
echo "Exit code: $?"
```

Expected: Exit code should be `2` (blocked).

If it's `0` or `1`, there's a bug. Please [report it](#reporting-issues).

---

## Detection Issues

### False Positives

False positives occur when noexec blocks a legitimate, safe command.

#### Example 1: Safe rm commands blocked

**Problem:**

```bash
rm -rf ./node_modules  # Blocked, but this is safe!
```

**Why it triggers:**
The destructive-commands detector sees `rm -rf` and flags it as dangerous.

**Current status:**
This is a known limitation. The detector uses conservative patterns.

**Workaround (coming in v0.3.0):**

```bash
# Temporarily disable noexec for one command
# (not yet implemented)
```

**How to identify:**

- Command operates on relative paths (`.`, `./`, subdirectories)
- Target is a build artifact (`node_modules`, `dist`, `build`)
- You're in a safe development environment

#### Example 2: Git force with lease blocked

**Problem:**

```bash
git push --force-with-lease  # Blocked, but this is safer!
```

**Why it triggers:**
Current git-force-operations detector blocks all `--force` variants.

**Status:**
This is a bug. `--force-with-lease` should be allowed.

**Workaround:**
Use verbose force-with-lease syntax:

```bash
git push --force-with-lease=HEAD
```

#### Example 3: Testing commands with dummy credentials

**Problem:**

```bash
export API_KEY="test_key_12345"  # Blocked, but this is a test!
```

**Why it triggers:**
The credential-leak detector doesn't distinguish between real and dummy credentials.

**How to adjust:**

The detector uses **entropy analysis** to avoid flagging obviously fake credentials:

- `password=test` → Not flagged (too short)
- `api_key=12345` → Not flagged (low entropy)
- `secret=sk-real-looking-key-123456789` → Flagged (looks real)

If your test credentials look realistic, they'll be flagged. Use obviously fake values:

```bash
# These won't trigger:
export API_KEY="test"
export SECRET="dummy"
export PASSWORD="123"

# These will trigger:
export API_KEY="sk-proj-1234567890abcdefghij"
export SECRET="live_sk_test_1234567890"
```

### False Negatives

False negatives occur when noexec **doesn't** block a dangerous command.

#### Example 1: Obfuscated credentials

**Problem:**

```bash
# This gets blocked:
echo $AWS_SECRET_ACCESS_KEY

# But this doesn't:
KEY=$AWS_SECRET_ACCESS_KEY && echo $KEY
```

**Why it's missed:**
The detector looks for direct environment variable references, not indirect assignments.

**What to do:**
[Report it](#reporting-issues) with the specific command pattern so we can improve the detector.

#### Example 2: Service-specific tokens not detected

**Problem:**

```bash
curl -H "Authorization: Bearer sk_live_abcdef123456" stripe.com/api
```

Currently, only generic patterns are detected. Service-specific patterns (Stripe `sk_live_`, Twilio `AC...`, etc.) are in development.

**Status:**
Coming in v0.2.0. See [ROADMAP.md](ROADMAP.md).

**Workaround:**
Be cautious with live API keys in commands. Use environment variables instead:

```bash
curl -H "Authorization: Bearer $STRIPE_SECRET_KEY" stripe.com/api
# This WILL be caught by env-var-leak detector
```

#### How to report missing patterns

If you find a dangerous command that noexec doesn't catch:

1. **Don't include real credentials** in your report
2. Create a minimal example with dummy data
3. [Open an issue](#reporting-issues) with:
   - The command pattern
   - What detector should catch it
   - Why it's dangerous

### Understanding Severity Levels

noexec uses three severity levels:

#### High Severity

**What it means:**
Immediate risk of credential exposure, data loss, or system damage.

**Examples:**

- Echoing AWS credentials to stdout
- `rm -rf /` on system directories
- `git push --force` to main branch
- Dumping all environment variables

**What to do:**
DO NOT run these commands. Investigate why the AI suggested it.

#### Medium Severity

**What it means:**
Potentially risky, depends on context.

**Examples:**

- Environment variable in export statement (not being sent anywhere)
- Git operations on local branches
- Destructive commands in safe directories

**What to do:**
Review the command carefully. It might be safe in your specific context.

#### Low Severity

**What it means:**
Minor concern, unlikely to cause immediate harm.

**Examples:**

- Test patterns in development
- Logging with sensitive variable names (but no actual secrets)

**What to do:**
Probably safe, but good to be aware.

---

## Debugging

### How to test a specific command locally

You can test noexec detection without running the command:

```bash
# Test a command
echo '{"command": "rm -rf /"}' | noexec analyze --hook PreToolUse
echo "Exit code: $?"
```

**Exit codes:**

- `0` = Command allowed (no issues detected)
- `2` = Command blocked (security issue detected)
- `1` = Error in analysis (but command allowed to fail-open)

**Example test session:**

```bash
# Test dangerous command
$ echo '{"command": "echo $AWS_SECRET_KEY"}' | noexec analyze --hook PreToolUse
⚠️  Security issues detected:
[HIGH] Environment variable containing sensitive data detected in command output or network request
  Detector: env-var-leak

$ echo $?
2

# Test safe command
$ echo '{"command": "ls -la"}' | noexec analyze --hook PreToolUse
$ echo $?
0
```

### Running detectors in isolation

Each detector is a separate module. To test a specific detector:

**1. Find the detector:**

Detectors are in `src/detectors/`:

- `credential-leak.ts` - API keys, tokens, passwords
- `destructive-commands.ts` - `rm -rf`, `dd`, fork bombs
- `git-force-operations.ts` - Force pushes, hard resets
- `env-var-leak.ts` - Environment variable exposure

**2. Create a test file:**

```typescript
// test-detector.ts
import { detectCredentialLeak } from './src/detectors/credential-leak';

(async () => {
  const result = await detectCredentialLeak({
    command: 'echo AKIAIOSFODNN7EXAMPLE',
  });
  console.log(result);
})();
```

**3. Run it:**

```bash
npx ts-node test-detector.ts
```

**Output:**

```json
{
  "severity": "high",
  "message": "Credential leak detected",
  "detector": "credential-leak"
}
```

### Verbose output options

Currently, noexec doesn't have a verbose/debug mode. Output is limited to:

- Security issues detected (stderr)
- Exit code (0, 1, or 2)

**Coming in v0.3.0:**

```bash
noexec analyze --hook PreToolUse --verbose
```

**Workaround:**

Add debugging to the analyze command:

```bash
# In ~/.claude/settings.json, modify the hook:
{
  "command": "noexec analyze --hook PreToolUse 2>&1 | tee -a ~/.noexec.log"
}
```

This logs all output to `~/.noexec.log`.

### Test mode

You can run the full test suite locally:

```bash
# Clone the repo
git clone https://github.com/emilgelman/noexec.git
cd noexec

# Install dependencies
npm install

# Run all tests
npm test

# Run specific test file
npx vitest src/detectors/__tests__/credential-leak.test.ts

# Run tests in watch mode
npm run test:watch

# Run tests with UI
npm run test:ui
```

**Test coverage report:**

```bash
npm run test:coverage
```

This generates a detailed coverage report in `coverage/index.html`.

---

## Common Questions

### "Why did this trigger?"

#### Example 1: `echo $API_KEY`

**Detector:** `env-var-leak`  
**Severity:** High  
**Why:** Echoing environment variables to stdout can expose secrets in logs, terminal history, or AI assistant output.

**Safe alternatives:**

```bash
# Check if variable exists without exposing it
if [ -z "$API_KEY" ]; then
  echo "API_KEY is not set"
else
  echo "API_KEY is set"
fi

# Use it directly in your application
./myapp --api-key "$API_KEY"  # Still blocked, but safer
```

#### Example 2: `rm -rf ./node_modules`

**Detector:** `destructive-commands`  
**Severity:** High  
**Why:** The pattern `rm -rf` is inherently dangerous. The detector is conservative.

**Why this is a false positive:**
This is a safe operation in development contexts.

**Status:**
Improving in v0.2.0 with safe path whitelists.

#### Example 3: `git push --force origin main`

**Detector:** `git-force-operation`  
**Severity:** High  
**Why:** Force pushing to `main` can overwrite other people's work and rewrite shared history.

**Safe alternatives:**

```bash
# Use force-with-lease (checks remote hasn't changed)
git push --force-with-lease origin main

# Push to a feature branch instead
git push --force origin feature/my-work

# Better: avoid force push entirely
git pull --rebase origin main
git push origin main
```

#### Example 4: `curl -d "data=$SECRET" api.example.com`

**Detector:** `env-var-leak`  
**Severity:** High  
**Why:** Sending environment variables in network requests can expose secrets to third parties.

**Context matters:**

- If `api.example.com` is your own API → might be fine
- If it's a third party → dangerous
- If it's in logs → definitely dangerous

### "How to whitelist a path/pattern?"

**Current status:** Not yet implemented.

**Coming in v0.3.0:**

Create `noexec.config.json` in your home directory or project root:

```json
{
  "whitelist": {
    "paths": ["./node_modules", "./dist", "./build", "/tmp"],
    "patterns": ["^npm install", "^yarn install", "rm -rf \\./[a-z-]+_modules"]
  }
}
```

**Workaround:**

Temporarily disable noexec by editing `~/.claude/settings.json` and removing the `PreToolUse` hook.

### "How to add custom patterns?"

You can fork noexec and add your own detectors.

**1. Create a new detector:**

```typescript
// src/detectors/my-detector.ts
import type { Detection, ToolUseData } from '../types';

export function detectMyPattern(toolUseData: ToolUseData): Promise<Detection | null> {
  const command = toolUseData.command || '';

  // Your detection logic
  if (command.includes('dangerous-pattern')) {
    return Promise.resolve({
      severity: 'high',
      message: 'Custom dangerous pattern detected',
      detector: 'my-detector',
    });
  }

  return Promise.resolve(null);
}
```

**2. Register it:**

```typescript
// src/commands/analyze.ts
import { detectMyPattern } from '../detectors/my-detector';

const detectors = [
  detectDestructiveCommand,
  detectGitForceOperation,
  detectCredentialLeak,
  detectEnvVarLeak,
  detectMyPattern, // Add here
];
```

**3. Rebuild and test:**

```bash
npm run build
npm link
echo '{"command": "dangerous-pattern"}' | noexec analyze --hook PreToolUse
```

**Want to contribute?**

If your detector is useful for others, please [open a PR](https://github.com/emilgelman/noexec/pulls)! See [CONTRIBUTING.md](CONTRIBUTING.md).

### "Performance concerns?"

noexec is designed to be fast:

**Benchmarks (from `test/integration/performance.test.ts`):**

- Simple command (`ls -la`): **<10ms** (actual pattern matching)
- Complex command (multi-part with detections): **<20ms**
- Large payload (10KB command): **<500ms**

These include Node.js startup time. Actual regex matching is **<1ms** per detector.

**Why it's fast:**

1. **Regex-based:** No external calls, no parsing, just pattern matching
2. **Optimized patterns:** Only necessary checks, no redundant work
3. **Fail-fast:** Stops on first detection (unless multiple detections occur)
4. **Local only:** No network calls, no I/O

**When performance matters:**

If you're running thousands of commands in a loop, noexec adds ~10-50ms per command. For typical AI assistant workflows (a few commands per minute), this is negligible.

---

## Reporting Issues

### What information to include

When reporting a bug or issue, include:

1. **noexec version:**

   ```bash
   npm list -g noexec
   ```

2. **Node.js version:**

   ```bash
   node --version
   ```

3. **Operating system:**

   ```bash
   uname -a  # Linux/macOS
   ver       # Windows
   ```

4. **Platform:**
   - Claude Code version
   - Or other AI CLI you're using

5. **The command that triggered the issue:**

   ```bash
   # Anonymize any real secrets!
   echo '{"command": "your-command-here"}' | noexec analyze --hook PreToolUse
   ```

6. **Expected behavior:**
   - "Should be allowed" (false positive)
   - "Should be blocked" (false negative)

7. **Actual behavior:**
   - Exit code
   - Error messages
   - stdout/stderr output

### How to create a minimal reproduction

**Good bug report:**

````markdown
## Bug: False positive on safe rm command

**Command:**

```bash
rm -rf ./dist
```
````

**Expected:** Should be allowed (removing build directory)

**Actual:** Blocked with "Destructive command detected"

**Test case:**

```bash
$ echo '{"command": "rm -rf ./dist"}' | noexec analyze --hook PreToolUse
⚠️  Security issues detected:
[HIGH] Destructive command detected
  Detector: destructive-commands

$ echo $?
2
```

**Environment:**

- noexec: 0.1.0
- Node.js: v18.17.0
- OS: Ubuntu 22.04
- Platform: Claude Code 1.2.0

````

**Bad bug report:**

```markdown
It doesn't work. Fix it.
````

### GitHub issue templates

When opening an issue on [GitHub](https://github.com/emilgelman/noexec/issues), use these templates:

#### Bug Report

```markdown
**Describe the bug**
A clear description of what's wrong.

**To Reproduce**
Steps to reproduce the behavior:

1. Run command '...'
2. See error

**Expected behavior**
What should happen instead.

**Environment:**

- noexec version: [e.g., 0.1.0]
- Node.js version: [e.g., 18.17.0]
- OS: [e.g., macOS 13.4]
- Platform: [e.g., Claude Code 1.2.0]

**Additional context**
Any other relevant information.
```

#### False Positive

````markdown
**Command being blocked:**

```bash
your-safe-command-here
```
````

**Why it's safe:**
Explain why this command should be allowed.

**Detector that triggered:**
[e.g., destructive-commands, credential-leak]

**Suggested fix:**
How should the detector be adjusted?

````

#### False Negative

```markdown
**Dangerous command NOT blocked:**
```bash
dangerous-command-here
````

**Why it's dangerous:**
Explain the security risk.

**Expected detector:**
Which detector should catch this?

**Suggested pattern:**
What pattern/rule should be added?

````

#### Feature Request

```markdown
**Feature description:**
What feature would you like to see?

**Use case:**
Why is this useful?

**Proposed implementation:**
If you have ideas on how to implement it.
````

---

## Still Need Help?

- 📖 [Read the full documentation](README.md)
- 💬 [Open a GitHub issue](https://github.com/emilgelman/noexec/issues)
- 🔒 [Security vulnerabilities](SECURITY.md)
- 🤝 [Contributing guide](CONTRIBUTING.md)

**Found this guide helpful?** Star ⭐ the repo on [GitHub](https://github.com/emilgelman/noexec)!
