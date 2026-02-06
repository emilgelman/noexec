# Real-World Testing Suite

This directory contains real-world scenario tests for noexec validation.

## Structure

- `scenarios/` - Real-world command scenarios
- `projects/` - Test against actual open-source projects
- `benchmarks/` - Performance testing with 100+ commands
- `reports/` - Test results and analysis

## Test Categories

### 1. Common Developer Workflows

- Git operations (clone, push, pull, rebase)
- Deployment scripts (Docker, Kubernetes, CI/CD)
- Package management (npm, pip, cargo)
- File operations (cleanup, backups)

### 2. Known CVEs and Attack Vectors

- Supply chain attacks (typosquatting packages)
- Credential exfiltration attempts
- Destructive command injections
- Environment variable leaks

### 3. False Positive Analysis

- Testing against popular repos (Next.js, React, Vue, etc.)
- CI/CD pipelines from real projects
- Legitimate scripts that should pass

### 4. Performance Testing

- 100+ command samples
- Memory profiling
- Latency measurement
- Scalability testing

## Running Tests

```bash
# Run all real-world scenarios
npm run test:real-world

# Run specific category
npm run test:scenarios
npm run test:projects
npm run test:benchmarks

# Generate reports
npm run test:report
```
