import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

describe('CLI Integration Tests', () => {
  let testDir: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    // Create a temporary directory for each test
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'noexec-test-'));
    originalHome = process.env.HOME;
    process.env.HOME = testDir;
  });

  afterEach(() => {
    // Clean up
    process.env.HOME = originalHome;
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe('noexec init', () => {
    it('should create Claude settings directory if it does not exist', () => {
      const claudeDir = path.join(testDir, '.claude');
      expect(fs.existsSync(claudeDir)).toBe(false);

      execSync('node dist/cli.js init --platform claude', {
        cwd: path.join(__dirname, '../..'),
        stdio: 'pipe',
      });

      expect(fs.existsSync(claudeDir)).toBe(true);
    });

    it('should create settings.json with noexec hook', () => {
      const settingsPath = path.join(testDir, '.claude', 'settings.json');

      execSync('node dist/cli.js init --platform claude', {
        cwd: path.join(__dirname, '../..'),
        stdio: 'pipe',
      });

      expect(fs.existsSync(settingsPath)).toBe(true);

      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      expect(settings.hooks).toBeDefined();
      expect(settings.hooks.PreToolUse).toBeDefined();
      expect(settings.hooks.PreToolUse).toHaveLength(1);
      expect(settings.hooks.PreToolUse[0].matcher).toBe('Bash');
      expect(settings.hooks.PreToolUse[0].hooks[0].command).toContain('noexec analyze');
    });

    it('should update existing hook if already configured', () => {
      const claudeDir = path.join(testDir, '.claude');
      const settingsPath = path.join(claudeDir, 'settings.json');

      // Create initial config with old hook
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

      // Run init again
      execSync('node dist/cli.js init --platform claude', {
        cwd: path.join(__dirname, '../..'),
        stdio: 'pipe',
      });

      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      expect(settings.hooks.PreToolUse).toHaveLength(1);
    });

    it('should preserve other hooks when adding noexec', () => {
      const claudeDir = path.join(testDir, '.claude');
      const settingsPath = path.join(claudeDir, 'settings.json');

      // Create config with existing hook
      fs.mkdirSync(claudeDir, { recursive: true });
      fs.writeFileSync(
        settingsPath,
        JSON.stringify({
          hooks: {
            PreToolUse: [
              {
                matcher: 'Python',
                hooks: [{ type: 'command', command: 'some-other-tool' }],
              },
            ],
          },
        })
      );

      execSync('node dist/cli.js init --platform claude', {
        cwd: path.join(__dirname, '../..'),
        stdio: 'pipe',
      });

      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      expect(settings.hooks.PreToolUse).toHaveLength(2);
      expect(settings.hooks.PreToolUse.some((h) => h.matcher === 'Python')).toBe(true);
      expect(settings.hooks.PreToolUse.some((h) => h.matcher === 'Bash')).toBe(true);
    });

    it('should fail with unknown platform', () => {
      expect(() => {
        execSync('node dist/cli.js init --platform unknown', {
          cwd: path.join(__dirname, '../..'),
          stdio: 'pipe',
        });
      }).toThrow();
    });
  });
});
