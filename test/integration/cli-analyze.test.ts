import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

describe('CLI Analyze - Integration Tests', () => {
  const cliPath = path.join(__dirname, '../..', 'dist/cli.js');

  describe('Credential Leak Detection', () => {
    it('should detect AWS credentials in command', () => {
      const input = JSON.stringify({
        command: 'echo AKIAIOSFODNN7EXAMPLE',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect GitHub token', () => {
      const input = JSON.stringify({
        command: 'curl -H "Authorization: Bearer ghp_1234567890123456789012345678901234567890"',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect API key assignment', () => {
      const input = JSON.stringify({
        command: 'export API_KEY="sk-1234567890123456789012345678901234567890123456"',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });
  });

  describe('Destructive Command Detection', () => {
    it('should detect rm -rf /', () => {
      const input = JSON.stringify({
        command: 'rm -rf /',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect dd to device', () => {
      const input = JSON.stringify({
        command: 'dd if=/dev/zero of=/dev/sda',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect fork bomb', () => {
      const input = JSON.stringify({
        command: ':() { : | : & }; :',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });
  });

  describe('Git Force Operations Detection', () => {
    it('should detect git push --force', () => {
      const input = JSON.stringify({
        command: 'git push --force origin main',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect git reset --hard', () => {
      const input = JSON.stringify({
        command: 'git reset --hard HEAD~5',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should allow git branch -D (local branch deletion)', () => {
      const input = JSON.stringify({
        command: 'git branch -D feature-branch',
      });

      // Local branch deletion is safe and should not throw
      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });
  });

  describe('Environment Variable Leak Detection', () => {
    it('should detect echoing AWS credentials', () => {
      const input = JSON.stringify({
        command: 'echo $AWS_SECRET_ACCESS_KEY',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });

    it('should detect API key in curl', () => {
      const input = JSON.stringify({
        command: 'curl https://api.example.com -H "Authorization: $API_KEY"',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).toThrow();
    });
  });

  describe('Multi-detector triggering', () => {
    it('should detect multiple issues in one command', () => {
      const input = JSON.stringify({
        command: 'rm -rf / && echo $AWS_SECRET_KEY && git push --force origin main',
      });

      let stderr = '';
      try {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      } catch (error: unknown) {
        if (error && typeof error === 'object' && 'stderr' in error) {
          stderr = String(error.stderr);
        }
      }

      // Should detect multiple issues
      expect(stderr).toContain('destructive');
      expect(stderr).toContain('env-var-leak');
      expect(stderr).toContain('git-force-operation');
    });
  });

  describe('Safe commands', () => {
    it('should allow safe ls command', () => {
      const input = JSON.stringify({
        command: 'ls -la',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });

    it('should allow safe git operations', () => {
      const input = JSON.stringify({
        command: 'git status',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });

    it('should allow safe npm commands', () => {
      const input = JSON.stringify({
        command: 'npm install',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });
  });

  describe('Error handling', () => {
    it('should handle empty stdin gracefully', () => {
      expect(() => {
        execSync(`echo '' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });

    it('should handle invalid JSON gracefully', () => {
      expect(() => {
        execSync(`echo 'not json' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow(); // Should exit 0 on error to not block execution
    });

    it('should handle malformed tool data gracefully', () => {
      const input = JSON.stringify({
        // Missing command field
        data: 'something',
      });

      expect(() => {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
      }).not.toThrow();
    });
  });

  describe('Exit codes', () => {
    it('should exit with code 2 when detection found', () => {
      const input = JSON.stringify({
        command: 'rm -rf /',
      });

      try {
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
        expect.fail('Should have thrown');
      } catch (error: unknown) {
        if (error && typeof error === 'object' && 'status' in error) {
          expect(error.status).toBe(2);
        }
      }
    });

    it('should exit with code 0 when no detection', () => {
      const input = JSON.stringify({
        command: 'ls -la',
      });

      const result = execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
        encoding: 'utf-8',
        stdio: 'pipe',
      });

      expect(result).toBeDefined();
    });
  });
});
