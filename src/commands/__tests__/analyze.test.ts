import { describe, it, expect } from 'vitest';
import { analyzeStdin } from '../analyze';

describe('analyzeStdin', () => {
  it('should return empty array when input is empty', async () => {
    const result = await analyzeStdin('');
    expect(result).toEqual([]);
  });

  it('should return empty array when input is whitespace', async () => {
    const result = await analyzeStdin('   \n  ');
    expect(result).toEqual([]);
  });

  it('should throw on invalid JSON', async () => {
    await expect(analyzeStdin('not json')).rejects.toThrow();
  });

  it('should return detections for dangerous command', async () => {
    const input = JSON.stringify({
      command: 'rm -rf /',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].severity).toBe('high');
    expect(detections[0].detector).toBe('destructive-command');
  });

  it('should return empty array for safe command', async () => {
    const input = JSON.stringify({
      command: 'ls -la',
    });

    const detections = await analyzeStdin(input);
    expect(detections).toEqual([]);
  });

  it('should return multiple detections for command with multiple issues', async () => {
    const input = JSON.stringify({
      command: 'rm -rf / && echo $AWS_SECRET_KEY && git push --force',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThanOrEqual(3);

    const detectorNames = detections.map((d) => d.detector);
    expect(detectorNames).toContain('destructive-command');
    expect(detectorNames).toContain('env-var-leak');
    expect(detectorNames).toContain('git-force-operation');
  });

  it('should detect credential leaks', async () => {
    const input = JSON.stringify({
      command: 'curl -H "Authorization: Bearer ghp_1234567890123456789012345678901234567890"',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].detector).toBe('credential-leak');
  });

  it('should detect git force operations', async () => {
    const input = JSON.stringify({
      command: 'git push --force origin main',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].detector).toBe('git-force-operation');
  });

  it('should detect environment variable leaks', async () => {
    const input = JSON.stringify({
      command: 'echo $AWS_SECRET_ACCESS_KEY',
    });

    const detections = await analyzeStdin(input);
    expect(detections.length).toBeGreaterThan(0);
    expect(detections[0].detector).toBe('env-var-leak');
  });

  it('should handle commands with no command field', async () => {
    const input = JSON.stringify({
      someOtherField: 'value',
    });

    const detections = await analyzeStdin(input);
    expect(detections).toEqual([]);
  });
});
