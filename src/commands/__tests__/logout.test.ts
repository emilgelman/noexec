import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logoutCommand } from '../logout';

describe('logoutCommand', () => {
  let testDir: string;
  let originalHome: string | undefined;
  let originalExit: typeof process.exit;
  let exitCode: number | undefined;
  let originalLog: typeof console.log;
  let originalError: typeof console.error;
  let logOutput: string[] = [];
  let errorOutput: string[] = [];

  beforeEach(() => {
    // Create temp directory
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'noexec-unit-test-'));
    originalHome = process.env.HOME;
    process.env.HOME = testDir;

    // Mock process.exit
    exitCode = undefined;
    originalExit = process.exit;
    process.exit = vi.fn((code?: string | number | null) => {
      exitCode = typeof code === 'number' ? code : 0;
      throw new Error(`process.exit called with code ${code}`);
    }) as never;

    // Mock console.log
    logOutput = [];
    originalLog = console.log;
    console.log = vi.fn((...args: unknown[]) => {
      logOutput.push(args.join(' '));
    });

    // Mock console.error
    errorOutput = [];
    originalError = console.error;
    console.error = vi.fn((...args: unknown[]) => {
      errorOutput.push(args.join(' '));
    });
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    process.exit = originalExit;
    console.log = originalLog;
    console.error = originalError;
    vi.clearAllMocks();
  });

  it('should show message if no config exists', async () => {
    try {
      logoutCommand();
    } catch {
      // Expected - process.exit throws
    }

    expect(logOutput.some((line) => line.includes('No configuration found'))).toBe(true);
    expect(exitCode).toBe(0);
  });

  it('should switch from team mode to free mode', async () => {
    // Create config with team mode
    const configDir = path.join(testDir, '.noexec');
    const configPath = path.join(configDir, 'config.json');

    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          mode: 'team',
          platform: {
            enabled: true,
            apiUrl: 'https://platform.noexec.io/api',
            apiKey: 'test-api-key',
            teamId: 'test-team-id',
          },
        },
        null,
        2
      ),
      'utf-8'
    );

    try {
      logoutCommand();
    } catch {
      // Expected - process.exit throws
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mode).toBe('free');
    expect(config.platform.enabled).toBe(false);
    expect(config.platform.apiKey).toBe('');
    expect(config.platform.teamId).toBe('');

    expect(logOutput.some((line) => line.includes('Successfully logged out'))).toBe(true);
    expect(exitCode).toBe(0);
  });

  it('should show message if already in free mode', async () => {
    // Create config with free mode
    const configDir = path.join(testDir, '.noexec');
    const configPath = path.join(configDir, 'config.json');

    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({ mode: 'free' }, null, 2), 'utf-8');

    try {
      logoutCommand();
    } catch {
      // Expected - process.exit throws
    }

    expect(logOutput.some((line) => line.includes('Already in free mode'))).toBe(true);
    expect(exitCode).toBe(0);
  });

  it('should clear credentials even if mode is not set', async () => {
    // Create config with platform but no mode
    const configDir = path.join(testDir, '.noexec');
    const configPath = path.join(configDir, 'config.json');

    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          platform: {
            enabled: true,
            apiUrl: 'https://platform.noexec.io/api',
            apiKey: 'test-api-key',
            teamId: 'test-team-id',
          },
        },
        null,
        2
      ),
      'utf-8'
    );

    try {
      logoutCommand();
    } catch {
      // Expected - process.exit throws
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mode).toBe('free');
    expect(config.platform.apiKey).toBe('');
    expect(exitCode).toBe(0);
  });
});
