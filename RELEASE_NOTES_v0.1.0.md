# noexec v0.1.0 - Initial Release

**Runtime security for AI coding assistants** - Stop dangerous commands before they execute.

## 🎉 First Release!

noexec is now available to protect your AI coding assistant sessions from dangerous commands and credential leaks.

## Installation

```bash
npm install -g noexec
noexec init
```

## Features in v0.1.0

### 🔒 Security Detectors (5 total)

1. **Credential Leak Detection** - Blocks exposure of:
   - AWS credentials (access keys, secret keys)
   - GitHub tokens (PAT, classic tokens)
   - GCP service account keys
   - Azure connection strings
   - Generic API keys and secrets

2. **Destructive Command Detection** - Prevents:
   - Dangerous file operations (`rm -rf /`, `dd if=/dev/zero`)
   - Filesystem formatting (`mkfs`, `wipefs`)
   - Fork bombs
   - System file overwrites

3. **Git Force Operation Detection** - Blocks:
   - Force push (`git push --force`)
   - Hard reset (`git reset --hard`)
   - Force clean (`git clean -fdx`)
   - Force branch deletion (`git branch -D`)

4. **Environment Variable Leak Detection** - Catches:
   - Secrets in echo commands (`echo $AWS_SECRET_KEY`)
   - Credentials in curl/wget (`curl -H "Token: $GITHUB_TOKEN"`)
   - Export of sensitive variables

5. **Magic String Detector** - Testing/proof-of-concept detector

### 🔌 Platform Support

- ✅ **Claude Code** via PreToolUse hooks
- 🔜 GitHub Copilot CLI (coming in v0.2.0)
- 🔜 Cursor (coming soon)
- 🔜 Continue.dev (coming soon)

### 📚 Documentation

- Comprehensive README with examples
- Contributing guidelines
- Security vulnerability reporting policy
- GitHub issue/PR templates

### 🧪 Testing

- Test suite demonstrating all detectors
- Manual testing scripts included

## What's Next?

See our [roadmap](https://github.com/emilgelman/noexec#roadmap) for upcoming features.

### v0.2.0 (Next Release)
- Automated test framework with >80% coverage
- GitHub Copilot CLI support
- Additional detectors (network exfiltration, database operations)

### v0.3.0
- Configuration file support (`noexec.config.json`)
- Custom whitelist/blacklist
- Severity threshold settings

## Getting Started

```bash
# Install globally
npm install -g noexec

# Configure hooks (auto-detects Claude Code)
noexec init

# That's it! Your AI assistant is now protected
```

## Example: Blocked Command

```bash
# AI tries to run:
echo "Your AWS key is: $AWS_SECRET_ACCESS_KEY"

# noexec blocks it:
❌ Security issue detected: Environment variable containing sensitive data
   Detector: env-var-leak
   Severity: high
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](https://github.com/emilgelman/noexec/blob/main/CONTRIBUTING.md) for guidelines.

**Especially welcome:**
- 🔍 New security detectors
- 🔌 Platform integrations
- 🐛 Bug reports and fixes
- 📚 Documentation improvements

## Community

- ⭐ Star this repo if you find it useful
- 🐛 Report issues on [GitHub Issues](https://github.com/emilgelman/noexec/issues)
- 💬 Join discussions
- 🤝 Submit PRs

## License

MIT License - see [LICENSE](https://github.com/emilgelman/noexec/blob/main/LICENSE) for details.

---

**Made with ❤️ by [Emil Gelman](https://github.com/emilgelman)**

Thanks to all early users and contributors! 🎉
