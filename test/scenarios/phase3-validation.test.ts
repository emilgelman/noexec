import { describe, it, expect } from 'vitest';
import { detectGitForceOperation } from '../../src/detectors/git-force-operations';
import { detectDestructiveCommand } from '../../src/detectors/destructive-commands';
import { detectCredentialLeak } from '../../src/detectors/credential-leak';
import { detectEnvVarLeak } from '../../src/detectors/env-var-leak';

describe('Real-World Tests - Developer Workflows', () => {
  it('should not flag safe git operations', async () => {
    const safeCommands = [
      'git clone https://github.com/facebook/react.git',
      'git pull origin main',
      'git push origin feature/new-feature',
      'git branch -D old-feature', // Local branch deletion - should be SAFE
      'git stash',
    ];

    for (const cmd of safeCommands) {
      const result = await detectGitForceOperation({ command: cmd });
      expect(result, `False positive on: ${cmd}`).toBeNull();
    }
  });

  it('should flag dangerous git operations', async () => {
    const dangerous = ['git push -f origin main', 'git push --force origin master'];

    for (const cmd of dangerous) {
      const result = await detectGitForceOperation({ command: cmd });
      expect(result, `Failed to detect: ${cmd}`).not.toBeNull();
    }
  });

  it('should not flag safe file operations', async () => {
    const safeCommands = ['rm -rf node_modules', 'rm -rf dist', 'rm -rf .next'];

    for (const cmd of safeCommands) {
      const result = await detectDestructiveCommand({ command: cmd });
      expect(result, `False positive on: ${cmd}`).toBeNull();
    }
  });

  it('should flag dangerous file operations', async () => {
    const dangerous = [
      { cmd: 'rm -rf /', reason: 'root deletion' },
      { cmd: 'chmod -R 000 /', reason: 'recursive chmod on root' },
      { cmd: 'chmod -R 777 /', reason: 'dangerous permissions on root' },
    ];

    for (const { cmd, reason } of dangerous) {
      const result = await detectDestructiveCommand({ command: cmd });
      expect(result, `Failed to detect ${reason}: ${cmd}`).not.toBeNull();
    }
  });
});

describe('Real-World Tests - Attack Vectors', () => {
  it('should detect credentials in git URLs', async () => {
    const cmd =
      'git remote add evil https://ghp_123456789012345678901234567890123456:@github.com/attacker/repo.git';

    const result = await detectCredentialLeak({ command: cmd });
    expect(result, 'Failed to detect credential in git URL').not.toBeNull();
  });

  it('should detect environment variable leaks', async () => {
    const commands = ['printenv | grep SECRET', 'env | grep -i key', 'cat /proc/self/environ'];

    for (const cmd of commands) {
      const result = await detectEnvVarLeak({ command: cmd });
      expect(result, `Failed to detect: ${cmd}`).not.toBeNull();
    }
  });

  it('should detect destructive commands', async () => {
    const commands = ['rm -rf / --no-preserve-root', 'dd if=/dev/zero of=/dev/sda', 'kill -9 -1'];

    for (const cmd of commands) {
      const result = await detectDestructiveCommand({ command: cmd });
      expect(result, `Failed to detect: ${cmd}`).not.toBeNull();
    }
  });
});
