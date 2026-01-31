# Project Structure

```
noexec/
├── src/                          # TypeScript source files
│   ├── cli.ts                    # Main CLI entry point
│   ├── commands/                 # Command implementations
│   │   ├── init.ts              # 'noexec init' - Configure hooks
│   │   └── analyze.ts           # 'noexec analyze' - Run detectors
│   └── detectors/               # Security detectors
│       ├── index.ts             # Detector types and interfaces
│       ├── magic-string.ts      # Example detector
│       └── credential-leak.ts   # Credential leak detector
├── dist/                        # Compiled JavaScript (generated)
├── package.json                 # Project metadata and dependencies
├── tsconfig.json               # TypeScript configuration
├── test-example.sh             # Example test script
└── README.md                   # Documentation
```

## Key Files

### src/cli.ts
Main CLI entry point. Uses Commander.js to define commands and options.

### src/commands/init.ts
Implements the `noexec init` command. Currently supports Claude Code configuration:
- Locates `~/.claude.json`
- Adds or updates PreToolUse hooks
- Configures noexec as a security layer

### src/commands/analyze.ts
Implements the `noexec analyze` command:
- Reads tool use data from stdin
- Runs all registered detectors
- Returns exit code 0 (allow) or 2 (block)

### src/detectors/
Security detectors that analyze tool usage:
- Each detector is an async function that returns `Detection | null`
- Detectors are easily extensible
- Currently includes:
  - `magic-string.ts` - Example detector for "test_me"
  - `credential-leak.ts` - Detects API keys, tokens, passwords

## Adding New Detectors

1. Create a new file in `src/detectors/`
2. Export an async function with signature: `(toolUseData: any) => Promise<Detection | null>`
3. Register it in `src/commands/analyze.ts` detectors array

## Adding New Platforms

1. Add platform-specific initialization logic in `src/commands/init.ts`
2. Follow the Claude Code example pattern
3. Detect platform config file location
4. Update or create hook configuration
