import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { initCommand } from '../init';

describe('initCommand', () => {
  let testDir: string;
  let originalHome: string | undefined;
  let originalExit: typeof process.exit;
  let exitCode: number | undefined;
  let originalLog: typeof console.log;
  let logOutput: string[] = [];

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
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    process.exit = originalExit;
    console.log = originalLog;
  });

  it('should create .claude directory if it does not exist', async () => {
    const claudeDir = path.join(testDir, '.claude');
    expect(fs.existsSync(claudeDir)).toBe(false);

    await initCommand({ platform: 'claude' });

    expect(fs.existsSync(claudeDir)).toBe(true);
  });

  it('should create settings.json with correct structure', async () => {
    await initCommand({ platform: 'claude' });

    const settingsPath = path.join(testDir, '.claude', 'settings.json');
    expect(fs.existsSync(settingsPath)).toBe(true);

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(settings).toHaveProperty('hooks');
    expect(settings.hooks).toHaveProperty('PreToolUse');
    expect(Array.isArray(settings.hooks.PreToolUse)).toBe(true);
  });

  it('should add noexec hook configuration', async () => {
    await initCommand({ platform: 'claude' });

    const settingsPath = path.join(testDir, '.claude', 'settings.json');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));

    const bashHook = settings.hooks.PreToolUse.find(
      (h: { matcher: string }) => h.matcher === 'Bash'
    );
    expect(bashHook).toBeDefined();
    expect(bashHook.hooks).toHaveLength(1);
    expect(bashHook.hooks[0].type).toBe('command');
    expect(bashHook.hooks[0].command).toContain('noexec analyze');
  });

  it('should preserve existing settings when adding hook', async () => {
    const claudeDir = path.join(testDir, '.claude');
    const settingsPath = path.join(claudeDir, 'settings.json');

    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      settingsPath,
      JSON.stringify({
        someOtherSetting: 'value',
        hooks: {
          PreToolUse: [
            {
              matcher: 'Python',
              hooks: [{ type: 'command', command: 'other-tool' }],
            },
          ],
        },
      })
    );

    await initCommand({ platform: 'claude' });

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(settings.someOtherSetting).toBe('value');
    expect(settings.hooks.PreToolUse).toHaveLength(2);
    expect(settings.hooks.PreToolUse.some((h: { matcher: string }) => h.matcher === 'Python')).toBe(
      true
    );
    expect(settings.hooks.PreToolUse.some((h: { matcher: string }) => h.matcher === 'Bash')).toBe(
      true
    );
  });

  it('should update existing noexec hook instead of duplicating', async () => {
    const claudeDir = path.join(testDir, '.claude');
    const settingsPath = path.join(claudeDir, 'settings.json');

    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      settingsPath,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: 'Bash',
              hooks: [{ type: 'command', command: 'noexec analyze --hook PreToolUse' }],
            },
          ],
        },
      })
    );

    await initCommand({ platform: 'claude' });

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(settings.hooks.PreToolUse).toHaveLength(1);
  });

  it('should exit with error for unknown platform', async () => {
    try {
      await initCommand({ platform: 'unknown' });
    } catch (error) {
      // Expected
    }

    expect(exitCode).toBe(1);
  });

  it('should log success message', async () => {
    await initCommand({ platform: 'claude' });

    expect(logOutput.some((line) => line.includes('Successfully configured'))).toBe(true);
  });
});
