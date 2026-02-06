# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-06

### 🎉 First Stable Release

noexec v1.0.0 is production-ready! This release includes comprehensive security detectors, extensive testing, and a polished user experience.

### Added

- **Enhanced Security Detectors**
  - Destructive command detector with safe path allowlisting
  - Git force operation detector with branch protection
  - Advanced credential leak detector with entropy analysis
  - Environment variable leak detector
  - Magic string detector for hardcoded sensitive data
- **User Experience Improvements**
  - 🎨 Colored console output with clear severity indicators
  - 💡 Helpful suggestions for each detector type
  - Better error messages and graceful failure modes
  - Improved CLI help text
- **Comprehensive Testing**
  - 164 unit and integration tests
  - Performance benchmarks
  - End-to-end CLI testing
  - 100% detector coverage
- **Quality Infrastructure**
  - Full TypeScript support with type definitions
  - ESLint + Prettier code formatting
  - Husky pre-commit hooks
  - GitHub Actions CI/CD pipeline
  - Automated npm publishing workflow
- **Documentation**
  - Architecture documentation (ARCHITECTURE.md)
  - Detector reference guide (DETECTORS.md)
  - Troubleshooting guide (TROUBLESHOOTING.md)
  - Contributing guidelines (CONTRIBUTING.md)
  - Security policy (SECURITY.md)
  - npm publish checklist

### Changed

- Improved false positive detection in all detectors
- Better entropy analysis for credential detection
- More comprehensive destructive command patterns
- Enhanced error handling with fail-open strategy

### Fixed

- False positives on safe rm commands (e.g., `rm -rf ./node_modules`)
- Placeholder detection in credential scanner
- Edge cases in git force operation detection
- JSON parsing error handling

## [0.1.0] - 2026-01-31

### Added

- Initial open source release
- Basic CLI with `init` and `analyze` commands
- Claude Code platform support
- PreToolUse hook integration
- Magic string detector (proof of concept)
- Credential leak detector (AWS, GCP, Azure, GitHub, API keys)
- README with installation and usage instructions
- TypeScript build system
- Manual test suite (`test-example.sh`)
- MIT License
- Contributing guidelines
- Security policy

### Known Issues

- No automated test framework yet
- Only Claude Code platform supported
- Limited detector library
- No configuration file support

[1.0.0]: https://github.com/emilgelman/noexec/releases/tag/v1.0.0
[0.1.0]: https://github.com/emilgelman/noexec/releases/tag/v0.1.0
