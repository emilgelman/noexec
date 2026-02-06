# Configuration Guide

NoExec provides a flexible configuration system that allows you to customize detector behavior, thresholds, and global settings.

## Quick Start

Generate a default configuration file:

```bash
noexec init --config
```

This creates `noexec.config.json` in your project root with all available options.

## Configuration File Locations

NoExec looks for configuration files in the following order (first found wins):

1. **Custom path** (via `--config` flag): `noexec analyze --config path/to/config.json`
2. **Project root**: `./noexec.config.json`
3. **User home directory**: `~/.noexec/config.json`

If no configuration file is found, NoExec uses sensible defaults.

## Configuration Structure

```json
{
  "detectors": {
    "credential-leak": { ... },
    "destructive-commands": { ... },
    "git-force-operations": { ... },
    "env-var-leak": { ... },
    "magic-string": { ... }
  },
  "globalSettings": {
    "minSeverity": "medium",
    "exitOnDetection": true,
    "jsonOutput": false
  }
}
```

## Detector Configuration

All detectors share common fields:

- **`enabled`** (boolean): Enable or disable the detector
- **`severity`** (string): Severity level for detections: `"low"`, `"medium"`, or `"high"`

### credential-leak

Detects credentials and API keys in commands.

```json
{
  "credential-leak": {
    "enabled": true,
    "severity": "high",
    "customPatterns": [],
    "minEntropy": 3.0,
    "ignorePlaceholders": true
  }
}
```

**Fields:**

- `customPatterns` (array of strings): Additional regex patterns to detect as credentials
- `minEntropy` (number): Minimum Shannon entropy threshold for generic credential patterns (default: 3.0)
- `ignorePlaceholders` (boolean): Skip placeholder-looking values like "your-api-key-here" (default: true)

**Example:**

```json
{
  "credential-leak": {
    "enabled": true,
    "severity": "high",
    "customPatterns": ["mycompany_[a-zA-Z0-9]{32}", "custom-token-[0-9]+"],
    "minEntropy": 4.0,
    "ignorePlaceholders": true
  }
}
```

### destructive-commands

Detects commands that could cause data loss or system damage.

```json
{
  "destructive-commands": {
    "enabled": true,
    "severity": "high",
    "safePaths": ["./node_modules", "./dist"],
    "additionalPatterns": []
  }
}
```

**Fields:**

- `safePaths` (array of strings): Paths that are safe to delete (e.g., build artifacts)
- `additionalPatterns` (array of strings): Additional regex patterns to flag as destructive

**Example:**

```json
{
  "destructive-commands": {
    "enabled": true,
    "severity": "high",
    "safePaths": ["./node_modules", "./dist", "./build", "./target", "./.next", "./out"],
    "additionalPatterns": ["\\btruncate\\b.*--all", "\\bdrop\\s+database\\b"]
  }
}
```

### git-force-operations

Detects dangerous git operations that can rewrite history or cause data loss.

```json
{
  "git-force-operations": {
    "enabled": true,
    "severity": "high",
    "protectedBranches": ["main", "master"],
    "allowForceWithLease": true
  }
}
```

**Fields:**

- `protectedBranches` (array of strings): Branch names that should never be force-pushed
- `allowForceWithLease` (boolean): Allow `--force-with-lease` (safer than `--force`)

**Example:**

```json
{
  "git-force-operations": {
    "enabled": true,
    "severity": "high",
    "protectedBranches": ["main", "master", "production", "staging", "develop"],
    "allowForceWithLease": true
  }
}
```

### env-var-leak

Detects environment variables containing secrets being exposed.

```json
{
  "env-var-leak": {
    "enabled": true,
    "severity": "high",
    "sensitiveVars": ["API_KEY", "SECRET"]
  }
}
```

**Fields:**

- `sensitiveVars` (array of strings): Additional environment variable names to flag as sensitive

**Example:**

```json
{
  "env-var-leak": {
    "enabled": true,
    "severity": "high",
    "sensitiveVars": ["COMPANY_API_KEY", "INTERNAL_TOKEN", "DB_CREDENTIALS", "SERVICE_PASSWORD"]
  }
}
```

### magic-string

Detects magic test strings (used for testing the system).

```json
{
  "magic-string": {
    "enabled": true,
    "severity": "high"
  }
}
```

This detector has no additional configuration options.

## Global Settings

```json
{
  "globalSettings": {
    "minSeverity": "medium",
    "exitOnDetection": true,
    "jsonOutput": false
  }
}
```

**Fields:**

- `minSeverity` (string): Minimum severity level to report (`"low"`, `"medium"`, or `"high"`)
  - `"high"`: Only report high-severity issues
  - `"medium"`: Report medium and high-severity issues
  - `"low"`: Report all issues
- `exitOnDetection` (boolean): Exit with code 2 when issues are detected (default: true)
- `jsonOutput` (boolean): Output detections as JSON instead of human-readable format (default: false)

## Use Cases

### Development Environment (Relaxed)

```json
{
  "detectors": {
    "credential-leak": {
      "enabled": true,
      "severity": "high"
    },
    "destructive-commands": {
      "enabled": true,
      "severity": "medium",
      "safePaths": ["./node_modules", "./dist", "./build", "./.next"]
    },
    "git-force-operations": {
      "enabled": false
    },
    "env-var-leak": {
      "enabled": true,
      "severity": "medium"
    },
    "magic-string": {
      "enabled": false
    }
  },
  "globalSettings": {
    "minSeverity": "medium",
    "exitOnDetection": true,
    "jsonOutput": false
  }
}
```

### Production/CI Environment (Strict)

```json
{
  "detectors": {
    "credential-leak": {
      "enabled": true,
      "severity": "high",
      "minEntropy": 4.0
    },
    "destructive-commands": {
      "enabled": true,
      "severity": "high",
      "safePaths": []
    },
    "git-force-operations": {
      "enabled": true,
      "severity": "high",
      "protectedBranches": ["main", "master", "production", "staging"],
      "allowForceWithLease": false
    },
    "env-var-leak": {
      "enabled": true,
      "severity": "high"
    },
    "magic-string": {
      "enabled": true,
      "severity": "high"
    }
  },
  "globalSettings": {
    "minSeverity": "high",
    "exitOnDetection": true,
    "jsonOutput": true
  }
}
```

### Audit Mode (No Blocking)

```json
{
  "globalSettings": {
    "minSeverity": "low",
    "exitOnDetection": false,
    "jsonOutput": true
  }
}
```

## Validation

Validate your configuration file:

```bash
noexec validate-config
noexec validate-config path/to/config.json
```

This checks for:

- Valid JSON syntax
- Correct field types
- Valid severity levels
- Valid detector names
- Required fields present

## Partial Configuration

You don't need to specify all options. NoExec merges your configuration with defaults:

```json
{
  "detectors": {
    "credential-leak": {
      "minEntropy": 4.0
    }
  }
}
```

This only changes the `minEntropy` setting; all other options keep their default values.

## Environment-Specific Configs

Use different configs for different environments:

```bash
# Development
noexec analyze --config config/dev.json

# CI/CD
noexec analyze --config config/ci.json

# Production
noexec analyze --config config/prod.json
```

## Troubleshooting

### Issue: Config not loading

**Solution:** Check file locations in order:

1. Is `--config` path correct?
2. Does `./noexec.config.json` exist in current directory?
3. Does `~/.noexec/config.json` exist?

### Issue: Validation errors

**Solution:** Run `noexec validate-config` to see detailed error messages with paths to problematic fields.

### Issue: Too many false positives

**Solutions:**

- Increase `minEntropy` for `credential-leak`
- Add paths to `safePaths` for `destructive-commands`
- Disable specific detectors with `"enabled": false`
- Raise `minSeverity` in global settings

### Issue: Missing detections

**Solutions:**

- Lower `minEntropy` for `credential-leak`
- Add custom patterns to detectors
- Lower `minSeverity` in global settings

## Advanced: JSON Output

For integration with other tools, use JSON output:

```bash
noexec analyze --config config.json < input.json > output.json
```

Example output:

```json
{
  "detections": [
    {
      "severity": "high",
      "message": "Service-specific credential detected",
      "detector": "credential-leak"
    }
  ]
}
```

This is useful for:

- CI/CD pipelines
- Custom reporting tools
- Security dashboards
- Automated alerts
