import { describe, it, expect } from 'vitest';
import { detectCredentialLeak } from '../credential-leak';

describe('detectCredentialLeak', () => {
  it('should detect AWS access key patterns', async () => {
    const toolData = {
      command: 'echo AKIAIOSFODNN7EXAMPLE',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
    expect(result?.detector).toBe('credential-leak');
  });

  it('should detect GitHub personal access tokens', async () => {
    const toolData = {
      command: 'curl -H "Authorization: token ghp_1234567890123456789012345678901234567890"',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });

  it('should detect GitHub classic tokens', async () => {
    const toolData = {
      command:
        'git clone https://gho_1234567890123456789012345678901234567890@github.com/user/repo',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });

  it('should detect GitHub fine-grained tokens', async () => {
    const toolData = {
      command:
        'export GITHUB_TOKEN=github_pat_11ABCDEFG1234567890123_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });

  it('should detect generic API keys', async () => {
    const toolData = {
      command: 'api_key=sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });

  it('should detect API keys with various formats', async () => {
    const testCases = [
      'api_key=abcdefghijklmnopqrstuvwxyz123456',
      'apikey=abcdefghijklmnopqrstuvwxyz123456',
      'secret_key=abcdefghijklmnopqrstuvwxyz123456',
      'access-token=abcdefghijklmnopqrstuvwxyz123456',
    ];

    for (const command of testCases) {
      const result = await detectCredentialLeak({ command });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    }
  });

  it('should not detect safe commands', async () => {
    const toolData = {
      command: 'echo "Hello World"',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).toBeNull();
  });

  it('should not detect short strings that look like keys', async () => {
    const toolData = {
      command: 'key=short',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).toBeNull();
  });

  it('should detect credentials in complex commands', async () => {
    const toolData = {
      command:
        'curl -X POST https://api.example.com -H "Authorization: Bearer ghp_1234567890123456789012345678901234567890" -d "data"',
    };

    const result = await detectCredentialLeak(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high');
  });
});
