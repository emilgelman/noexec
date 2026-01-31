# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**noexec** is a security scanner for agentic CLIs (like Claude Code, GitHub Copilot CLI, Gemini CLI). It prevents dangerous commands and credential leaks using CLI hooks. The project is distributed as a global npm package that configures hooks in supported platforms.

## Common Commands

### Building and Development
```bash
npm run build          # Compile TypeScript to dist/
npm run dev            # Watch mode for development
npm link               # Link for local testing
```

### Testing
```bash
./test-example.sh      # Run manual test suite (requires built code in dist/)
```

Note: There is no automated test framework configured yet (`npm test` will fail).

### Debugging
```bash
npm run debug:init     # Debug init command with Node inspector
npm run debug:analyze  # Debug analyze command with test input
```

## Architecture

### Hook-Based Security Model

noexec works by intercepting tool execution in agentic CLIs:

1. **Configuration Phase** (`noexec init`): Modifies platform config files (e.g., `~/.claude/settings.json`) to register a PreToolUse hook
2. **Runtime Analysis** (`noexec analyze`): Called automatically by the platform hook before each Bash command execution
3. **Detection & Blocking**: Runs all registered detectors; exits with code 2 to block execution if issues found

### Data Flow

```
Platform (Claude Code) → PreToolUse Hook → noexec analyze (stdin: tool data) → Detectors → Exit Code (0=allow, 2=block)
```

### Core Components

**CLI Entry Point** (`src/cli.ts`): Uses Commander.js to define two main commands: `init` and `analyze`.

**Commands** (`src/commands/`):
- `init.ts`: Platform-specific configuration. Currently only supports Claude Code by modifying `~/.claude/settings.json`. Adds/updates PreToolUse hooks with matcher "Bash".
- `analyze.ts`: Reads tool use data from stdin, runs all registered detectors sequentially, outputs issues to stderr, and exits with appropriate code.

**Detectors** (`src/detectors/`):
- Each detector implements the `Detector` type: `(toolUseData: any) => Promise<Detection | null>`
- Detectors analyze the entire tool use JSON payload (not just command strings)
- Run sequentially; first detection triggers immediate blocking
- Currently registered: `detectMagicString`, `detectCredentialLeak`

### Adding New Detectors

1. Create a new file in `src/detectors/` (e.g., `my-detector.ts`)
2. Export an async function matching the `Detector` type
3. Import and add to the `detectors` array in `src/commands/analyze.ts`
4. Rebuild with `npm run build`

Example detector structure:
```typescript
import { Detection } from './index';

export async function detectMyIssue(toolUseData: any): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  if (/* detection logic */) {
    return {
      severity: 'high',
      message: 'Description of the security issue',
      detector: 'my-detector-name'
    };
  }

  return null;
}
```

### Adding New Platforms

To support additional agentic CLIs beyond Claude Code:

1. Add platform detection and configuration logic in `src/commands/init.ts`
2. Create a new `initPlatformName()` function following the `initClaude()` pattern
3. Understand the platform's hook mechanism and config file location
4. Update the hook configuration to call `noexec analyze --hook PreToolUse`

## Configuration Files

- **~/.claude/settings.json**: Claude Code configuration file modified by `noexec init`. Contains hooks configuration.
- **package.json**: Defines the `noexec` binary pointing to `dist/cli.js`
- **tsconfig.json**: Compiles from `src/` to `dist/` as CommonJS for Node.js compatibility

## Exit Codes

- `0`: No security issues detected (allow execution)
- `2`: Security issue detected (block execution)
- `1`: General errors (platform unknown, etc.)

## Important Notes

- The tool MUST be built (`npm run build`) before it can be used, as the binary points to `dist/cli.js`
- Hook changes require restarting the Claude Code session to take effect
- Detectors receive the full tool use JSON payload, not just command strings
- All detector errors are caught and result in exit code 0 (fail-open for safety)
