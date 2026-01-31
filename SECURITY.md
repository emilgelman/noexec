# Security Policy

## Reporting a Vulnerability

We take the security of noexec seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email security details to: **emil.gelman@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-14 days
  - Medium/Low: 14-30 days

### Disclosure Policy

- We will coordinate disclosure timing with you
- We prefer coordinated disclosure after a fix is available
- We will credit you in the release notes (unless you prefer anonymity)

## Security Best Practices

When using noexec:

1. **Keep Updated**: Always use the latest version (`npm update -g noexec`)
2. **Review Detectors**: Understand what each detector does
3. **Test Before Deploying**: Test in non-production first
4. **Report Issues**: Help us improve by reporting false positives/negatives

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

As we're in early development (0.x), only the latest version receives security updates.

## Security Features

noexec is designed with security in mind:

- **No Network Access**: The CLI runs entirely locally (no data sent to servers)
- **Open Source**: All code is auditable
- **Fail-Open Design**: If detectors error, commands are allowed (prevents blocking legitimate work)
- **Minimal Dependencies**: Reduces attack surface

## Known Limitations

- **Obfuscation**: Heavily obfuscated commands may bypass detectors
- **Platform-Dependent**: Relies on platform hook mechanisms working correctly
- **Performance**: Complex regex in detectors may impact CLI responsiveness
- **False Negatives**: No security tool is 100% effective

## Future Security Enhancements

- [ ] Detector sandboxing
- [ ] Rate limiting for hook invocations
- [ ] Telemetry for threat intelligence (opt-in only)
- [ ] Integration with CVE databases
- [ ] Support for custom allow/block lists

Thank you for helping keep noexec and its users secure!
