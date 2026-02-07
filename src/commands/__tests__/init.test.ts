import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import { initCommand } from '../init';
import * as apiClient from '../../api-client';

// Mock readline
vi.mock('readline', () => ({
  createInterface: vi.fn(),
}));

// Mock api-client
vi.mock('../../api-client', () => ({
  login: vi.fn(),
}));

describe('initCommand', () => {
  let testDir: string;
  let originalHome: string | undefined;
  let originalExit: typeof process.exit;
  let exitCode: number | undefined;
  let originalLog: typeof console.log;
  let originalError: typeof console.error;
  let logOutput: string[] = [];
  let errorOutput: string[] = [];

  // Mock readline responses
  let mockReadlineResponses: string[] = [];
  let responseIndex = 0;

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

    // Reset mock readline
    mockReadlineResponses = [];
    responseIndex = 0;

    vi.mocked(readline.createInterface).mockImplementation(() => {
      const mockRl = {
        question: vi.fn((prompt: string, callback: (answer: string) => void) => {
          const response = mockReadlineResponses[responseIndex] || '1';
          responseIndex++;
          callback(response);
        }),
        close: vi.fn(),
      };
      return mockRl as unknown as readline.Interface;
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

  it('should create .claude directory if it does not exist', async () => {
    const claudeDir = path.join(testDir, '.claude');
    expect(fs.existsSync(claudeDir)).toBe(false);

    mockReadlineResponses = ['1']; // Choose free mode
    await initCommand({ platform: 'claude' });

    expect(fs.existsSync(claudeDir)).toBe(true);
  });

  it('should create settings.json with correct structure', async () => {
    mockReadlineResponses = ['1']; // Choose free mode
    await initCommand({ platform: 'claude' });

    const settingsPath = path.join(testDir, '.claude', 'settings.json');
    expect(fs.existsSync(settingsPath)).toBe(true);

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(settings).toHaveProperty('hooks');
    expect(settings.hooks).toHaveProperty('PreToolUse');
    expect(Array.isArray(settings.hooks.PreToolUse)).toBe(true);
  });

  it('should add noexec hook configuration', async () => {
    mockReadlineResponses = ['1']; // Choose free mode
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

    mockReadlineResponses = ['1']; // Choose free mode
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

    mockReadlineResponses = ['1']; // Choose free mode
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
    mockReadlineResponses = ['1']; // Choose free mode
    await initCommand({ platform: 'claude' });

    expect(logOutput.some((line) => line.includes('configured in Claude settings'))).toBe(true);
  });

  it('should create free mode config when user chooses option 1', async () => {
    mockReadlineResponses = ['1']; // Choose free mode
    await initCommand({ platform: 'claude' });

    const configPath = path.join(testDir, '.noexec', 'config.json');
    expect(fs.existsSync(configPath)).toBe(true);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mode).toBe('free');
    expect(logOutput.some((line) => line.includes('Configured for local use'))).toBe(true);
  });

  it('should handle team mode authentication when user chooses option 2', async () => {
    const mockLoginResponse = {
      apiKey: 'test-api-key',
      teamId: 'test-team-id',
      teamName: 'Test Team',
    };

    vi.mocked(apiClient.login).mockResolvedValue(mockLoginResponse);

    // Mock responses: choice '2', email, password
    mockReadlineResponses = ['2', 'test@example.com', 'password123'];

    await initCommand({ platform: 'claude' });

    // Check that login was called
    expect(apiClient.login).toHaveBeenCalledWith('test@example.com', 'password123');

    // Check that config was saved with team mode
    const configPath = path.join(testDir, '.noexec', 'config.json');
    expect(fs.existsSync(configPath)).toBe(true);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mode).toBe('team');
    expect(config.platform).toBeDefined();
    expect(config.platform.apiKey).toBe('test-api-key');
    expect(config.platform.teamId).toBe('test-team-id');

    expect(logOutput.some((line) => line.includes('Logged in as'))).toBe(true);
  });

  it('should fall back to free mode if login fails and user chooses free', async () => {
    vi.mocked(apiClient.login).mockRejectedValue(new Error('Invalid credentials'));

    // Mock responses: choice '2', email, password, then 'free' on retry prompt
    mockReadlineResponses = ['2', 'test@example.com', 'wrongpassword', 'free'];

    await initCommand({ platform: 'claude' });

    // Check that config was saved with free mode
    const configPath = path.join(testDir, '.noexec', 'config.json');
    expect(fs.existsSync(configPath)).toBe(true);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mode).toBe('free');

    expect(errorOutput.some((line) => line.includes('Login failed'))).toBe(true);
    expect(logOutput.some((line) => line.includes('Configured for local use'))).toBe(true);
  });

  it('should detect already initialized config and show warning', async () => {
    // Create existing config
    const configDir = path.join(testDir, '.noexec');
    const configPath = path.join(configDir, 'config.json');

    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({ mode: 'free' }, null, 2), 'utf-8');

    mockReadlineResponses = ['1']; // This won't be used
    await initCommand({ platform: 'claude' });

    expect(logOutput.some((line) => line.includes('already initialized'))).toBe(true);
    expect(logOutput.some((line) => line.includes('Current mode: free'))).toBe(true);
    expect(logOutput.some((line) => line.includes('noexec login'))).toBe(true);
  });

  it('should not prompt for authentication if already initialized', async () => {
    // Create existing config
    const configDir = path.join(testDir, '.noexec');
    const configPath = path.join(configDir, 'config.json');

    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({ mode: 'team' }, null, 2), 'utf-8');

    await initCommand({ platform: 'claude' });

    expect(logOutput.some((line) => line.includes('already initialized'))).toBe(true);
    expect(logOutput.some((line) => line.includes('How would you like to use'))).toBe(false);
  });
});
