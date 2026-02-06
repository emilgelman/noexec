# Detector Analysis & Improvements

## Current Detector Review

### 1. Credential Leak Detector

**Current Patterns:**

- Generic: `api_key=...`, `password=...`, etc.
- AWS: `AKIA...` format
- GitHub: `ghp_...`, `gho_...`, `github_pat_...`
- OpenAI-style: `sk-...`

**Identified Issues:**

#### False Positives

1. **Example/Documentation strings**
   - `export API_KEY="example_key_here"` in docs
   - `password=placeholder` in examples
   - Test fixtures with dummy credentials

2. **Variable names without values**
   - `echo $API_KEY` (reference, not leak)
   - `--api-key $MY_KEY` (using var, not exposing)

3. **Short credentials**
   - `api_key=test` (too short to be real)
   - `password=123` (clearly not production)

#### False Negatives

1. **Missing service patterns**
   - Stripe: `sk_live_...`, `sk_test_...`
   - Twilio: `AC...` + auth token format
   - SendGrid: `SG....`
   - Slack: `xoxb-...`, `xoxp-...`
   - Discord: bot tokens
   - JWT tokens (base64 with 3 parts)

2. **Obfuscation**
   - Base64 encoded credentials
   - Split credentials across commands
   - Credentials in files being cat'd

3. **Environment file dumps**
   - `cat .env` exposing multiple secrets
   - `printenv` with no filtering

#### Improvements Needed

- ✅ Add entropy analysis (reject low-entropy like "test", "example")
- ✅ Add service-specific patterns (Stripe, Twilio, etc.)
- ✅ Detect base64-encoded secrets
- ✅ Context awareness: distinguish reference vs exposure
- ✅ Whitelist common placeholder patterns

---

### 2. Destructive Commands Detector

**Current Patterns:**

- `rm -rf` with dangerous paths
- `dd` disk operations
- `mkfs`, `fdisk`, `parted`
- Fork bombs
- `shred`, `wipefs`
- Overwrites to system files
- `chmod`/`chown` on system paths

**Identified Issues:**

#### False Positives

1. **Safe rm operations**
   - `rm -rf /tmp/my-build-dir` (temp dir is safe)
   - `rm -rf node_modules` (common dev task)
   - `rm -rf ./dist` (build output)

2. **Container/sandbox contexts**
   - Operations inside Docker might be safe
   - `/tmp` is usually safe to clean

#### False Negatives

1. **Disk filling attacks**
   - `:(){ :|:& };:` (fork bomb - DETECTED)
   - `dd if=/dev/zero of=largefile` (fill disk)
   - `yes | head -c 1000000000 > file`

2. **Process killers**
   - `kill -9 -1` (kill all processes)
   - `pkill -9 -U username`

3. **Network disruption**
   - `iptables -F` (flush firewall rules)
   - `ip link set eth0 down`

#### Improvements Needed

- ✅ Add safe path whitelist (`/tmp`, `./node_modules`, etc.)
- ✅ Detect disk-filling attacks
- ✅ Detect mass process killers
- ✅ Add context: relative paths safer than absolute
- ✅ Improve fork bomb detection (more variants)

---

### 3. Git Force Operations Detector

**Current Patterns:**

- `git push --force` (not `--force-with-lease`)
- `git reset --hard`
- `git clean -f`
- `git checkout --force`
- `git branch -D`
- `git filter-branch`
- `git reflog expire/delete`

**Identified Issues:**

#### False Positives

1. **Force-with-lease is safer**
   - `git push --force-with-lease` should be allowed
   - Currently blocked by our pattern

2. **Personal branches**
   - Force push to `feature/*` less risky
   - Force push to `fix/*` less risky

3. **Safe resets**
   - `git reset --hard HEAD` (discard local changes only)
   - In detached HEAD state

#### False Negatives

1. **Interactive rebase**
   - `git rebase -i` can rewrite history
   - Not currently detected

2. **Amend + force push**
   - `git commit --amend && git push -f`

#### Improvements Needed

- ✅ Allow `--force-with-lease`
- ✅ Add branch name context (less strict for feature branches)
- ✅ Detect `git rebase -i`
- ✅ Consider protected branch lists

---

### 4. Environment Variable Leak Detector

**Current Patterns:**

- Sensitive var names: `AWS_*`, `API_KEY`, `PASSWORD`, etc.
- Dangerous contexts: `echo`, `curl`, logging, git commits

**Identified Issues:**

#### False Positives

1. **Checking if var exists**
   - `[ -z "$API_KEY" ]` (conditional check)
   - `if [ -n "$SECRET" ]` (existence test)

2. **Passing to safe commands**
   - `myapp --api-key "$API_KEY"` (app consumes it)
   - Docker build args sometimes necessary

#### False Negatives

1. **Indirect exposure**
   - `env | grep SECRET` (list all secrets)
   - `printenv` (dump everything)
   - `set | grep KEY`

2. **File operations**
   - `cat .env` (exposing env file)
   - `cp .env backup.env` (copying secrets)

#### Improvements Needed

- ✅ Detect `env | grep`, `printenv`, `set` dumps
- ✅ Distinguish conditional checks from exposure
- ✅ Add file operation detection (`.env` files)

---

### 5. Magic String Detector

**Status:** Test detector only
**Action:** Remove before v1.0 or document as example

---

## Priority Improvements (This Session)

### High Priority

1. ✅ Credential leak: Add service-specific patterns (Stripe, Slack, etc.)
2. ✅ Credential leak: Add entropy check for false positives
3. ✅ Destructive: Add safe path whitelist
4. ✅ Git: Allow `--force-with-lease`
5. ✅ Env var: Detect indirect dumps (`env`, `printenv`)

### Medium Priority

6. ✅ Credential leak: Detect base64-encoded secrets
7. ✅ Destructive: Detect disk-filling attacks
8. ✅ Git: Detect interactive rebase

### Test Coverage

- ✅ Add tests for all new patterns
- ✅ Add tests for false positive fixes
- ✅ Maintain 100% detector coverage

---

## Implementation Plan

1. Update credential-leak.ts
2. Update destructive-commands.ts
3. Update git-force-operations.ts
4. Update env-var-leak.ts
5. Add corresponding tests
6. Run full test suite
7. Verify no regressions
8. Commit improvements
