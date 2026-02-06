import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000, // Integration tests may need more time
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.ts',
        '**/*.spec.ts',
        'vitest.config.ts',
        'eslint.config.js',
        'test/integration/**', // Integration tests test the CLI, not the source
        'src/cli.ts', // CLI entry point - tested via integration tests
        'src/types.ts', // Type definitions only
        'index.js', // Module export only
      ],
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 95,
        statements: 85,
      },
    },
  },
});
