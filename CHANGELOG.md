# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source release
- MIT License
- Contributing guidelines
- Security policy
- Changelog

## [0.1.0] - 2026-01-31

### Added
- Basic CLI with `init` and `analyze` commands
- Claude Code platform support
- PreToolUse hook integration
- Magic string detector (proof of concept)
- Credential leak detector (AWS, GCP, Azure, GitHub, API keys)
- README with installation and usage instructions
- TypeScript build system
- Manual test suite (`test-example.sh`)

### Known Issues
- No automated test framework yet
- Only Claude Code platform supported
- Limited detector library
- No configuration file support

[Unreleased]: https://github.com/emilgelman/noexec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/emilgelman/noexec/releases/tag/v0.1.0
