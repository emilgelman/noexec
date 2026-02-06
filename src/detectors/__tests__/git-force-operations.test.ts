import { describe, it, expect } from 'vitest';
import { detectGitForceOperation } from '../git-force-operations';

describe('detectGitForceOperation', () => {
  describe('force push', () => {
    it('should detect git push --force', async () => {
      const result = await detectGitForceOperation({
        command: 'git push --force origin main',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('git-force-operation');
    });

    it('should detect git push -f', async () => {
      const result = await detectGitForceOperation({
        command: 'git push -f origin feature-branch',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect force push to main branch', async () => {
      const result = await detectGitForceOperation({
        command: 'git push --force origin main',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect force push to master branch', async () => {
      const result = await detectGitForceOperation({
        command: 'git push -f origin master',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow force-with-lease', async () => {
      const result = await detectGitForceOperation({
        command: 'git push --force-with-lease origin main',
      });
      expect(result).toBeNull();
    });

    it('should allow normal push', async () => {
      const result = await detectGitForceOperation({
        command: 'git push origin main',
      });
      expect(result).toBeNull();
    });
  });

  describe('reset operations', () => {
    it('should detect git reset --hard', async () => {
      const result = await detectGitForceOperation({
        command: 'git reset --hard HEAD~1',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git reset --hard without ref', async () => {
      const result = await detectGitForceOperation({
        command: 'git reset --hard',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow soft reset', async () => {
      const result = await detectGitForceOperation({
        command: 'git reset --soft HEAD~1',
      });
      expect(result).toBeNull();
    });

    it('should allow mixed reset', async () => {
      const result = await detectGitForceOperation({
        command: 'git reset HEAD~1',
      });
      expect(result).toBeNull();
    });
  });

  describe('clean operations', () => {
    it('should detect git clean -f', async () => {
      const result = await detectGitForceOperation({
        command: 'git clean -f',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git clean -fdx', async () => {
      const result = await detectGitForceOperation({
        command: 'git clean -fdx',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git clean -df', async () => {
      const result = await detectGitForceOperation({
        command: 'git clean -df',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow git clean dry-run', async () => {
      const result = await detectGitForceOperation({
        command: 'git clean -n',
      });
      expect(result).toBeNull();
    });
  });

  describe('branch operations', () => {
    it('should allow git branch -D (local branch deletion is safe)', async () => {
      const result = await detectGitForceOperation({
        command: 'git branch -D old-branch',
      });
      expect(result).toBeNull(); // Local branch deletion is intentionally allowed
    });

    it('should allow normal branch deletion', async () => {
      const result = await detectGitForceOperation({
        command: 'git branch -d merged-branch',
      });
      expect(result).toBeNull();
    });

    it('should detect force-delete of remote branch', async () => {
      const result = await detectGitForceOperation({
        command: 'git push origin :feature-branch',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('checkout operations', () => {
    it('should detect git checkout --force', async () => {
      const result = await detectGitForceOperation({
        command: 'git checkout --force main',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git checkout -f', async () => {
      const result = await detectGitForceOperation({
        command: 'git checkout -f branch-name',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow normal checkout', async () => {
      const result = await detectGitForceOperation({
        command: 'git checkout main',
      });
      expect(result).toBeNull();
    });
  });

  describe('history rewriting', () => {
    it('should detect git filter-branch', async () => {
      const result = await detectGitForceOperation({
        command: 'git filter-branch --tree-filter "rm -f passwords.txt" HEAD',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git reflog expire', async () => {
      const result = await detectGitForceOperation({
        command: 'git reflog expire --expire=now --all',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git reflog delete', async () => {
      const result = await detectGitForceOperation({
        command: 'git reflog delete HEAD@{1}',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect git update-ref -d', async () => {
      const result = await detectGitForceOperation({
        command: 'git update-ref -d refs/heads/main',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe git commands', () => {
    it('should allow common safe git operations', async () => {
      const testCases = [
        'git status',
        'git log',
        'git diff',
        'git add .',
        'git commit -m "message"',
        'git pull origin main',
        'git fetch origin',
        'git merge feature-branch',
        'git rebase main',
        'git stash',
        'git branch',
      ];

      for (const command of testCases) {
        const result = await detectGitForceOperation({ command });
        expect(result).toBeNull();
      }
    });
  });
});
