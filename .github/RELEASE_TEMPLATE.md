# 🎉 noexec v1.0.0 - First Stable Release

We're excited to announce the first stable release of **noexec** – a runtime security scanner for AI coding assistants that prevents dangerous commands and credential leaks before they execute!

## 🚀 What's New in v1.0.0

### Enhanced Security Detection

- **5 Production-Ready Detectors**
  - 🔐 **Credential Leak Detector**: Advanced pattern matching with entropy analysis for GitHub tokens, AWS keys, API secrets, and more
  - 💥 **Destructive Command Detector**: Prevents data loss from dangerous operations like `rm -rf /`, `dd`, fork bombs, and mass process killers
  - 🔀 **Git Force Operation Detector**: Protects important branches from force-push operations
  - 🌍 **Environment Variable Leak Detector**: Prevents accidental export of sensitive environment variables
  - 🔮 **Magic String Detector**: Identifies hardcoded sensitive data in commands

### Improved User Experience

- **Beautiful CLI Output** 🎨
  - Color-coded severity levels (🚨 HIGH, ⚠️ MEDIUM, ℹ️ LOW)
  - Clear, actionable error messages
  - 💡 Helpful suggestions for each detection (e.g., "use --force-with-lease instead of --force")
  - Visual separators and formatting

- **Better Error Handling**
  - Graceful failure modes with fail-open strategy
  - Clear validation messages
  - Improved input handling

### Production-Grade Quality

- ✅ **130+ Tests** with comprehensive coverage
- 📚 **Complete Documentation** (architecture, detectors, troubleshooting)
- 🔧 **Full TypeScript Support** with type definitions
- 🚦 **CI/CD Pipeline** with automated testing and publishing
- 📦 **Optimized Package** with proper npm metadata and exports

## 📦 Installation

```bash
npm install -g noexec
noexec init
```

## 🎯 Quick Start

After installation, noexec automatically integrates with Claude Code to analyze commands before execution:

```bash
# The hook runs automatically when AI tries to execute commands
# Example blocked commands:
❌ rm -rf /home/user/important-data
❌ git push --force origin main
❌ export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
```

## 🔍 Key Features

- **Zero Configuration**: Works out of the box with sensible defaults
- **Low Latency**: < 20ms analysis time for most commands
- **Customizable**: Configure detectors, severity levels, and safe paths
- **Framework Agnostic**: Designed to work with any AI coding assistant
- **Open Source**: MIT licensed, community-driven development

## 📊 By the Numbers

- 5 security detectors
- 130+ unit and integration tests
- <20ms average analysis time
- 0 dependencies (except chalk for colors)
- 100% TypeScript

## 🙏 Thanks

This release wouldn't be possible without the testing and feedback from the community. Special thanks to early adopters who reported issues and helped improve the detectors!

## 🐛 Reporting Issues

Found a bug or have a feature request? [Open an issue on GitHub](https://github.com/emilgelman/noexec/issues)

## 📖 Learn More

- [Documentation](https://github.com/emilgelman/noexec#readme)
- [Architecture Guide](https://github.com/emilgelman/noexec/blob/main/ARCHITECTURE.md)
- [Detector Reference](https://github.com/emilgelman/noexec/blob/main/DETECTORS.md)
- [Contributing Guide](https://github.com/emilgelman/noexec/blob/main/CONTRIBUTING.md)

---

**Full Changelog**: https://github.com/emilgelman/noexec/blob/main/CHANGELOG.md
