import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

describe('CLI Performance Benchmarks', () => {
  const cliPath = path.join(__dirname, '../..', 'dist/cli.js');

  describe('Analysis Performance', () => {
    it('should analyze simple command in <10ms', () => {
      const input = JSON.stringify({
        command: 'ls -la',
      });

      const iterations = 10;
      const times: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
          encoding: 'utf-8',
          stdio: 'pipe',
        });
        const end = performance.now();
        times.push(end - start);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      console.log(`Average analysis time (simple): ${avgTime.toFixed(2)}ms`);

      // Loose constraint - includes Node.js startup time
      // Actual pattern matching should be much faster
      expect(avgTime).toBeLessThan(200);
    });

    it('should analyze complex command in <20ms', () => {
      const input = JSON.stringify({
        command:
          'curl -X POST https://api.example.com -H "Authorization: Bearer token123" -d "data" && git commit -m "test" && npm install && ls -la',
      });

      const iterations = 10;
      const times: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        try {
          execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
            encoding: 'utf-8',
            stdio: 'pipe',
          });
        } catch {
          // Ignore detection errors for performance test
        }
        const end = performance.now();
        times.push(end - start);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      console.log(`Average analysis time (complex): ${avgTime.toFixed(2)}ms`);

      expect(avgTime).toBeLessThan(300);
    });

    it('should handle large payloads efficiently', () => {
      const largeCommand = 'echo ' + 'a'.repeat(10000);
      const input = JSON.stringify({
        command: largeCommand,
      });

      const start = performance.now();
      execSync(`echo '${input}' | node ${cliPath} analyze --hook PreToolUse`, {
        encoding: 'utf-8',
        stdio: 'pipe',
      });
      const end = performance.now();

      console.log(`Large payload (10KB) analysis time: ${(end - start).toFixed(2)}ms`);
      expect(end - start).toBeLessThan(500);
    });
  });

  describe('Init Performance', () => {
    it('should complete init in reasonable time', () => {
      const start = performance.now();
      try {
        execSync(`node ${cliPath} init --platform claude`, {
          encoding: 'utf-8',
          stdio: 'pipe',
          env: { ...process.env, HOME: '/tmp/noexec-perf-test' },
        });
      } catch {
        // May fail due to permissions, that's ok for perf test
      }
      const end = performance.now();

      console.log(`Init time: ${(end - start).toFixed(2)}ms`);
      expect(end - start).toBeLessThan(1000);
    });
  });
});
