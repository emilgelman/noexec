import { describe, it, expect } from 'vitest';
import { detectMagicString } from '../magic-string';

describe('detectMagicString', () => {
  it('should detect magic string "test_me"', async () => {
    const toolData = {
      command: 'echo test_me'
    };

    const result = await detectMagicString(toolData);

    expect(result).not.toBeNull();
    expect(result?.severity).toBe('high'); // Magic string detector uses 'high' severity
    expect(result?.detector).toBe('magic-string');
    expect(result?.message).toContain('test_me');
  });

  it('should not detect other strings', async () => {
    const toolData = {
      command: 'echo hello world'
    };

    const result = await detectMagicString(toolData);

    expect(result).toBeNull();
  });

  it('should detect magic string in complex commands', async () => {
    const toolData = {
      command: 'curl https://api.example.com?query=test_me'
    };

    const result = await detectMagicString(toolData);

    expect(result).not.toBeNull();
  });
});
