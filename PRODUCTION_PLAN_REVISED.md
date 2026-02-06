# noexec Production Readiness Plan - REVISED

**Created:** 2026-02-06  
**Agent:** Sandcat 🐈  
**Owner:** Emil Gelman  
**Status:** Ready for execution - High quality focus

---

## Executive Summary

After code review with thinking mode enabled, I've identified key areas requiring attention to achieve production quality:

**Current Strengths:**

- ✅ 85 passing tests across 5 detectors
- ✅ Well-structured TypeScript codebase
- ✅ Clean detector pattern architecture
- ✅ Good test coverage per detector

**Critical Gaps:**

- ❌ No CI/CD pipeline
- ❌ No test coverage measurement
- ❌ No linting/code quality enforcement
- ❌ Detectors need refinement (false positive risk)
- ❌ No integration tests
- ❌ No benchmarking/performance validation

**Revised Focus:** Quality over speed. Build it right the first time.

---

## Phase 1: Foundation & Quality (v0.2.0) - 2 weeks

### Week 1: Quality Infrastructure

#### 1. Code Quality Setup [2-3 days]

**Priority: CRITICAL**

- [ ] **ESLint + Prettier**
  - Install and configure ESLint with TypeScript support
  - Add Prettier for consistent formatting
  - Configure rules focused on security and maintainability
  - Add pre-commit hooks (husky + lint-staged)
  - Fix all linting violations

- [ ] **Test Coverage Infrastructure**
  - Install `@vitest/coverage-v8`
  - Configure coverage thresholds (aim for 90%+)
  - Add coverage reports to gitignore
  - Document coverage targets in CONTRIBUTING.md

- [ ] **TypeScript Strictness**
  - Review tsconfig.json for strictness settings
  - Enable `strict: true` if not already
  - Fix any new type errors
  - Add `noUncheckedIndexedAccess` for safety

**Deliverable:** Clean, linted codebase with measurable coverage

---

#### 2. CI/CD Pipeline [2 days]

**Priority: CRITICAL**

**GitHub Actions Workflows:**

**a) Main CI Pipeline (`.github/workflows/ci.yml`)**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    strategy:
      matrix:
        node-version: [18, 20, 22]
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}

    steps:
      - Checkout code
      - Setup Node.js
      - Install dependencies
      - Run linting
      - Run tests
      - Upload coverage to Codecov
      - Build TypeScript
      - Run integration tests
```

**b) Security Audit (`.github/workflows/security.yml`)**

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 1' # Weekly

jobs:
  audit:
    - npm audit
    - Check for outdated dependencies
    - Run CodeQL analysis (if applicable)
```

**c) Release Pipeline (`.github/workflows/release.yml`)**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    - Run full test suite
    - Build package
    - Publish to npm (with provenance)
    - Create GitHub release with changelog
```

**Deliverable:** Automated testing on every PR, multi-platform validation

---

#### 3. Integration Tests [2 days]

**Priority: HIGH**

Create `test/integration/` directory with real-world scenarios:

**Test Cases:**

- [ ] CLI initialization flow (mocked filesystem)
- [ ] End-to-end analyze command with stdin
- [ ] Hook configuration modification (Claude settings.json)
- [ ] Error handling scenarios
- [ ] Multi-detector triggering
- [ ] Performance benchmarks (command analysis time)

**Test utilities:**

- Mock stdin/stdout/stderr
- Temporary test directories
- Snapshot testing for CLI output

**Deliverable:** 10+ integration tests covering critical user flows

---

### Week 2: Detector Quality & Documentation

#### 4. Detector Code Review & Refinement [3-4 days]

**Priority: HIGH**

**For EACH detector, perform:**

**a) False Positive Analysis**

- Review regex patterns for edge cases
- Add test cases for known false positives
- Implement context awareness where needed
- Consider command intent, not just patterns

**b) False Negative Analysis**

- Research real-world attack vectors
- Add tests for bypass attempts
- Review security research/CVE databases
- Add obfuscation detection

**c) Pattern Quality**

```typescript
// Current issue: Simple string matching
// Example from credential-leak.ts
/(?:api[_-]?key|apikey)/i

// Improvement: Context-aware detection
- Check if in echo/curl/network context
- Ignore comments and documentation
- Validate credential format (entropy check)
- Add support for environment variable expansion
```

**Specific Detector Improvements:**

**credential-leak.ts:**

- [ ] Add entropy analysis for random strings
- [ ] Detect base64-encoded credentials
- [ ] Add more service-specific patterns (Stripe, Twilio, etc.)
- [ ] Reduce false positives from example/dummy credentials
- [ ] Add context: is this in documentation vs actual command?

**destructive-commands.ts:**

- [ ] Whitelist safe directories (temp, cache)
- [ ] Detect rm with specific file targets (less dangerous)
- [ ] Add context: is this in a container/VM?
- [ ] Improve fork bomb detection (more variants)

**git-force-operations.ts:**

- [ ] Allow `--force-with-lease` (safer alternative)
- [ ] Add branch name context (force to feature/\* less risky)
- [ ] Detect interactive rebase (also dangerous)
- [ ] Add exceptions for force-push to personal branches

**env-var-leak.ts:**

- [ ] Current context detection is good, strengthen it
- [ ] Add detection for `env | grep SECRET`
- [ ] Detect `printenv` with sensitive vars
- [ ] Improve severity scoring based on context

**magic-string.ts:**

- [ ] This is just a test detector - document or remove for v1.0

**Deliverable:** Hardened detectors with <1% false positive rate

---

#### 5. Performance & Benchmarking [1 day]

**Priority: MEDIUM**

- [ ] Create `benchmark/` directory
- [ ] Benchmark each detector individually
- [ ] Benchmark full analysis pipeline
- [ ] Test with large payloads (10KB+ commands)
- [ ] Profile regex performance
- [ ] Target: <10ms per command analysis
- [ ] Document performance characteristics

**Deliverable:** Performance baseline and optimization targets

---

#### 6. Documentation Polish [1-2 days]

**Priority: HIGH**

**Update/Create:**

- [ ] README.md - Accurate feature list, all detectors documented
- [ ] ARCHITECTURE.md - System design, data flow, extensibility
- [ ] CONTRIBUTING.md - Detector development guide
- [ ] SECURITY.md - Vulnerability reporting, security guarantees
- [ ] CHANGELOG.md - Detailed v0.2.0 changes
- [ ] API.md - CLI command reference
- [ ] DETECTORS.md - Each detector documented with examples

**Documentation Standards:**

- Examples for every detector
- Screenshots/GIFs of CLI in action
- Clear architecture diagrams (mermaid)
- Troubleshooting section
- FAQ

**Deliverable:** Professional, comprehensive documentation

---

## Phase 2: Feature Complete (v0.3.0) - 1.5 weeks

### Configuration System [3-4 days]

**Design Goals:**

- Simple, intuitive configuration
- Support global and project-specific configs
- Backward compatible (sensible defaults)
- Validate configuration on load

**Configuration Schema (`noexec.config.json`):**

```json
{
  "version": "1.0",
  "detectors": {
    "credential-leak": {
      "enabled": true,
      "severity": "high",
      "whitelist": ["EXAMPLE_API_KEY", "FAKE_SECRET_FOR_TESTING"]
    },
    "destructive-commands": {
      "enabled": true,
      "allowedPaths": ["/tmp", "/var/tmp"],
      "denyPaths": ["/", "/home", "/etc"]
    },
    "git-force-operations": {
      "enabled": true,
      "allowForceWithLease": true,
      "protectedBranches": ["main", "master", "production"]
    },
    "env-var-leak": {
      "enabled": true,
      "customSecretPatterns": ["MY_CUSTOM_SECRET_*"]
    }
  },
  "global": {
    "severityThreshold": "medium",
    "exitOnFirstDetection": true,
    "verbose": false
  }
}
```

**Implementation:**

- [ ] Config loading from multiple locations (precedence order)
- [ ] Schema validation with helpful error messages
- [ ] `noexec config init` - generate default config
- [ ] `noexec config validate` - check config file
- [ ] `noexec config show` - display active config
- [ ] Config merge logic (global + project)

**Testing:**

- [ ] Unit tests for config loading
- [ ] Integration tests with various config combinations
- [ ] Error handling for invalid configs

**Deliverable:** Flexible configuration system with strong defaults

---

### UX Improvements [2-3 days]

**CLI Enhancements:**

- [ ] Better colored output (use chalk/picocolors)
- [ ] Progress indicators for slow operations
- [ ] Helpful error messages with suggestions
- [ ] `--debug` flag for troubleshooting
- [ ] `--dry-run` for testing detectors
- [ ] `--explain <detector>` - show detector details
- [ ] Exit code documentation in --help

**Output Formatting:**

```
❌ Security Issue Detected

  Detector: credential-leak
  Severity: HIGH

  Problem: GitHub personal access token detected in command

  Found: ghp_************************************

  Command: echo ghp_1234...

  Suggestion: Remove the credential from the command or use an
  environment variable. Never hardcode credentials in scripts.

  Learn more: https://noexec.dev/docs/detectors/credential-leak
```

**Deliverable:** Professional, helpful CLI experience

---

## Phase 3: Production Ready (v1.0.0) - 2 weeks

### Multi-Platform Support [4-5 days]

**Research & Implement:**

**1. GitHub Copilot CLI**

- [ ] Research hook mechanism (if available)
- [ ] Implement initialization logic
- [ ] Test with Copilot CLI
- [ ] Document setup process

**2. Cursor**

- [ ] Research extension API
- [ ] Implement integration
- [ ] Test thoroughly
- [ ] Document setup

**3. Continue.dev**

- [ ] Research plugin system
- [ ] Implement integration
- [ ] Test
- [ ] Document

**4. Other AI CLIs**

- [ ] Survey landscape for other tools
- [ ] Implement if feasible

**Fallback Strategy:**

- If direct integration not possible, provide shell wrapper
- Document manual setup process
- Create platform compatibility matrix

**Deliverable:** Multi-platform support or clear compatibility documentation

---

### Security Audit [2-3 days]

**Comprehensive Security Review:**

**1. Dependency Security**

- [ ] Run `npm audit` and fix all issues
- [ ] Review all dependencies (minimize attack surface)
- [ ] Pin dependency versions
- [ ] Set up Dependabot for updates

**2. Code Security**

- [ ] Review for injection vulnerabilities
- [ ] Validate all user inputs
- [ ] Check file permission handling
- [ ] Review error messages (no information leaks)
- [ ] Test privilege escalation scenarios

**3. Detector Security**

- [ ] ReDoS (Regular Expression Denial of Service) testing
- [ ] Regex complexity analysis
- [ ] Add timeouts for detector execution
- [ ] Test with malicious payloads

**4. Privacy Audit**

- [ ] Verify no network calls (except npm install)
- [ ] Check for telemetry/tracking (must be none)
- [ ] Review log output for sensitive data
- [ ] Verify config files don't leak info

**Deliverable:** Security audit report + fixes

---

### Final Testing & Polish [3-4 days]

**Cross-Platform Testing:**

- [ ] Ubuntu 20.04, 22.04, 24.04
- [ ] macOS 12, 13, 14
- [ ] Windows 10/11 (WSL2)
- [ ] Various shell environments (bash, zsh, fish)
- [ ] Different Node.js versions (18, 20, 22)

**Real-World Testing:**

- [ ] Install on fresh systems
- [ ] Test with actual AI coding assistants
- [ ] Collect feedback from beta users
- [ ] Fix any discovered issues

**Performance Validation:**

- [ ] Run benchmarks on all platforms
- [ ] Ensure <10ms analysis time
- [ ] Check memory usage
- [ ] Profile and optimize if needed

**Documentation Final Review:**

- [ ] Technical accuracy check
- [ ] Spell check and grammar
- [ ] Link validation
- [ ] Screenshot updates
- [ ] Version number updates

**Deliverable:** Production-ready v1.0.0 release

---

### Launch Preparation [2-3 days]

**Marketing Materials:**

- [ ] Create demo video (2-3 minutes)
- [ ] Create demo GIF for README
- [ ] Write launch blog post
- [ ] Prepare social media posts
- [ ] Create Product Hunt listing
- [ ] Prepare Hacker News post

**Community Setup:**

- [ ] Enable GitHub Discussions
- [ ] Create Discord server (optional)
- [ ] Add contributor guidelines
- [ ] Tag "good first issue" items
- [ ] Create roadmap for v2.0

**npm Package:**

- [ ] Final package.json review
- [ ] README for npm (may differ from GitHub)
- [ ] Keywords optimization
- [ ] Badge setup (CI, coverage, npm version)

**Deliverable:** Launch-ready materials

---

## Phase 4: Landing Page (v1.0.0 + Website) - 1.5 weeks

### Planning & Design [2 days]

**Domain:**

- [ ] Purchase noexec.dev (preferred)
- [ ] Set up DNS

**Technology:**

- Choice: **Next.js 14** (App Router)
- Reasoning:
  - Best for static sites with future blog potential
  - Great SEO support
  - Easy deployment (Vercel)
  - Modern, maintained
  - Component reusability

**Design System:**

- [ ] Choose color palette (consider dark mode first)
- [ ] Select typography (Inter + JetBrains Mono)
- [ ] Create basic component library
- [ ] Define spacing/sizing scale
- [ ] Icon set (Lucide React)

**Wireframes:**

- [ ] Hero section
- [ ] Problem/Solution
- [ ] Features grid
- [ ] How it works (diagram)
- [ ] Getting started
- [ ] Open source section
- [ ] Footer

**Deliverable:** Approved design and technology stack

---

### Development [5-6 days]

**Day 1-2: Setup & Hero**

- [ ] Initialize Next.js project
- [ ] Set up Tailwind CSS
- [ ] Create base layout
- [ ] Build hero section with CTA
- [ ] Add animated terminal demo (if time permits)

**Day 3: Problem & Solution**

- [ ] Build problem section with examples
- [ ] Build solution section with architecture diagram
- [ ] Add visual separator components

**Day 4: Features & How It Works**

- [ ] Features grid with icons
- [ ] Detector showcase
- [ ] Platform badges
- [ ] Interactive "how it works" diagram

**Day 5: Getting Started & Open Source**

- [ ] Installation steps component
- [ ] Code block with syntax highlighting
- [ ] GitHub stats (stars, contributors)
- [ ] Open source callout

**Day 6: Polish**

- [ ] Footer with links
- [ ] Mobile responsiveness
- [ ] Dark mode toggle
- [ ] Animations and transitions
- [ ] Loading states

**Key Components:**

```typescript
// Example: TerminalDemo.tsx
<TerminalWindow>
  <TerminalLine>$ npm install -g noexec</TerminalLine>
  <TerminalLine>$ noexec init</TerminalLine>
  <TerminalLine success>✓ noexec configured for Claude Code</TerminalLine>
</TerminalWindow>

// Example: DetectorCard.tsx
<DetectorCard
  icon={<ShieldCheck />}
  title="Credential Leak"
  description="Detects exposed API keys, tokens, and passwords"
  severity="high"
/>
```

**Deliverable:** Functional landing page

---

### Content & SEO [1-2 days]

**Content Writing:**

- [ ] Compelling hero copy
- [ ] Clear problem statement
- [ ] Benefit-focused feature descriptions
- [ ] Social proof (quotes, stats)
- [ ] FAQ section

**SEO Optimization:**

- [ ] Meta tags (title, description)
- [ ] OpenGraph tags (social sharing)
- [ ] Twitter Card tags
- [ ] Structured data (JSON-LD)
- [ ] Sitemap generation
- [ ] robots.txt

**Performance:**

- [ ] Image optimization (Next.js Image)
- [ ] Code splitting
- [ ] Lazy loading
- [ ] Font optimization
- [ ] Lighthouse score >95

**Deliverable:** SEO-optimized, high-performance website

---

### Launch [1 day]

**Deployment:**

- [ ] Deploy to Vercel
- [ ] Configure custom domain
- [ ] Set up SSL
- [ ] Test in production
- [ ] Set up analytics (Plausible/Vercel Analytics)

**Announcement:**

- [ ] Publish launch blog post
- [ ] Post to Product Hunt
- [ ] Post to Hacker News
- [ ] Share on Twitter/LinkedIn
- [ ] Post in relevant subreddits
- [ ] Share in dev communities (Discord, Slack groups)

**Deliverable:** Live website at noexec.dev

---

## Revised Timeline

**Phase 1 (v0.2.0):** 2 weeks

- Week 1: Quality infrastructure (linting, CI/CD, integration tests)
- Week 2: Detector refinement + documentation

**Phase 2 (v0.3.0):** 1.5 weeks

- Configuration system (3-4 days)
- UX improvements (2-3 days)

**Phase 3 (v1.0.0):** 2 weeks

- Multi-platform support (4-5 days)
- Security audit (2-3 days)
- Final testing & polish (3-4 days)
- Launch prep (2-3 days)

**Phase 4 (Landing Page):** 1.5 weeks

- Planning & design (2 days)
- Development (5-6 days)
- Content & SEO (1-2 days)
- Launch (1 day)

**Total: 7-8 weeks** (conservative, high-quality timeline)

---

## Success Criteria

**Code Quality:**

- [ ] 90%+ test coverage
- [ ] Zero linting errors
- [ ] All CI checks passing
- [ ] <1% false positive rate in detectors
- [ ] <10ms average analysis time

**Production Metrics (v1.0.0):**

- [ ] > 100 GitHub stars in first month
- [ ] > 1,000 npm downloads/week
- [ ] <5 P0/P1 bugs in first month
- [ ] Zero security vulnerabilities
- [ ] > 4.5/5 user satisfaction

**Website Metrics:**

- [ ] <2s page load time
- [ ] > 90 Lighthouse score
- [ ] > 30% install conversion rate
- [ ] > 10,000 unique visitors in first month

---

## Risk Mitigation

**Technical Risks:**

1. **Multi-platform integration may not be feasible**
   - Mitigation: Document workarounds, focus on quality for supported platforms

2. **Detector false positives**
   - Mitigation: Extensive testing, community feedback loop, config overrides

3. **Performance issues with complex regexes**
   - Mitigation: Benchmark early, use timeout limits, optimize patterns

**Schedule Risks:**

1. **7-8 weeks is aggressive**
   - Mitigation: Prioritize ruthlessly, cut nice-to-haves, quality > features

2. **Unexpected platform-specific bugs**
   - Mitigation: Test early and often, maintain platform compatibility matrix

---

## Next Steps (Immediate)

**Today (Week 1, Day 1):**

1. Set up ESLint + Prettier
2. Add pre-commit hooks
3. Create GitHub Actions CI workflow
4. Install coverage tooling
5. Run linting and fix violations

**This Week:**

- Complete quality infrastructure
- Start detector refinement
- Write integration tests

**Decision Needed from Emil:**

1. **Timeline**: Is 7-8 weeks acceptable? Or push for faster?
2. **Scope**: Any features to cut or add?
3. **Platform priority**: Focus on Claude Code only for v1.0, or delay for multi-platform?
4. **Website tech**: Next.js approved? Alternative preferences?

**Ready to start execution?** 🚀
