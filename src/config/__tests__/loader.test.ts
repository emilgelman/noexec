import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  loadConfig,
  generateConfigFile,
  validateConfigFile,
  ConfigValidationError,
} from '../loader';
import { DEFAULT_CONFIG } from '../defaults';

describe('Config Loader', () => {
  let testDir: string;

  beforeEach(() => {
    // Create a temporary test directory
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'noexec-test-'));
    process.chdir(testDir);
  });

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe('loadConfig', () => {
    it('should load default config when no file exists', () => {
      const config = loadConfig();
      expect(config).toEqual(DEFAULT_CONFIG);
    });

    it('should load and merge project config', () => {
      const customConfig = {
        detectors: {
          'credential-leak': {
            enabled: false,
            severity: 'low' as const,
            customPatterns: ['test'],
            minEntropy: 4.0,
            ignorePlaceholders: false,
          },
        },
        globalSettings: {
          minSeverity: 'low' as const,
          exitOnDetection: false,
          jsonOutput: true,
        },
      };

      fs.writeFileSync(
        path.join(testDir, 'noexec.config.json'),
        JSON.stringify(customConfig, null, 2)
      );

      const config = loadConfig();
      expect(config.detectors['credential-leak'].enabled).toBe(false);
      expect(config.detectors['credential-leak'].minEntropy).toBe(4.0);
      expect(config.globalSettings.jsonOutput).toBe(true);
      // Other detectors should still have defaults
      expect(config.detectors['destructive-commands'].enabled).toBe(true);
    });

    it('should load custom config path', () => {
      const customConfig = {
        detectors: {
          'magic-string': {
            enabled: false,
            severity: 'low' as const,
          },
        },
        globalSettings: {
          minSeverity: 'high' as const,
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      const customPath = path.join(testDir, 'custom-config.json');
      fs.writeFileSync(customPath, JSON.stringify(customConfig, null, 2));

      const config = loadConfig(customPath);
      expect(config.detectors['magic-string'].enabled).toBe(false);
    });

    it('should merge partial configs with defaults', () => {
      const partialConfig = {
        detectors: {
          'git-force-operations': {
            protectedBranches: ['develop', 'staging'],
          },
        },
      };

      fs.writeFileSync(
        path.join(testDir, 'noexec.config.json'),
        JSON.stringify(partialConfig, null, 2)
      );

      const config = loadConfig();
      // Merged field
      expect(config.detectors['git-force-operations'].protectedBranches).toEqual([
        'develop',
        'staging',
      ]);
      // Default fields should still exist
      expect(config.detectors['git-force-operations'].enabled).toBe(true);
      expect(config.detectors['git-force-operations'].severity).toBe('high');
      expect(config.globalSettings).toEqual(DEFAULT_CONFIG.globalSettings);
    });

    it('should throw on invalid JSON', () => {
      fs.writeFileSync(path.join(testDir, 'noexec.config.json'), 'invalid json{');

      expect(() => loadConfig()).toThrow(ConfigValidationError);
      expect(() => loadConfig()).toThrow(/Invalid JSON/);
    });

    it('should validate merged config', () => {
      const invalidConfig = {
        detectors: {
          'credential-leak': {
            enabled: 'yes', // Invalid boolean
            severity: 'high',
            customPatterns: [],
            minEntropy: 3.0,
            ignorePlaceholders: true,
          },
        },
        globalSettings: DEFAULT_CONFIG.globalSettings,
      };

      fs.writeFileSync(
        path.join(testDir, 'noexec.config.json'),
        JSON.stringify(invalidConfig, null, 2)
      );

      expect(() => loadConfig()).toThrow(ConfigValidationError);
    });
  });

  describe('generateConfigFile', () => {
    it('should generate default config file', () => {
      const configPath = generateConfigFile();

      expect(fs.existsSync(configPath)).toBe(true);
      expect(configPath).toBe(path.join(testDir, 'noexec.config.json'));

      const content = fs.readFileSync(configPath, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed).toEqual(DEFAULT_CONFIG);
    });

    it('should generate config at custom path', () => {
      const customPath = path.join(testDir, 'custom.json');
      const configPath = generateConfigFile(customPath);

      expect(fs.existsSync(configPath)).toBe(true);
      expect(configPath).toBe(customPath);
    });

    it('should throw if config file already exists', () => {
      fs.writeFileSync(path.join(testDir, 'noexec.config.json'), '{}');

      expect(() => generateConfigFile()).toThrow(/already exists/);
    });
  });

  describe('validateConfigFile', () => {
    it('should validate a valid config file', () => {
      const configPath = path.join(testDir, 'valid-config.json');
      fs.writeFileSync(configPath, JSON.stringify(DEFAULT_CONFIG, null, 2));

      expect(() => validateConfigFile(configPath)).not.toThrow();
    });

    it('should throw on missing file', () => {
      expect(() => validateConfigFile(path.join(testDir, 'missing.json'))).toThrow(/not found/);
    });

    it('should throw on invalid config', () => {
      const invalidConfig = {
        detectors: {
          'unknown-detector': {
            enabled: true,
            severity: 'high',
          },
        },
        globalSettings: DEFAULT_CONFIG.globalSettings,
      };

      const configPath = path.join(testDir, 'invalid.json');
      fs.writeFileSync(configPath, JSON.stringify(invalidConfig, null, 2));

      expect(() => validateConfigFile(configPath)).toThrow(ConfigValidationError);
    });

    it('should validate partial config merged with defaults', () => {
      const partialConfig = {
        detectors: {
          'credential-leak': {
            minEntropy: 5.0,
          },
        },
      };

      const configPath = path.join(testDir, 'partial.json');
      fs.writeFileSync(configPath, JSON.stringify(partialConfig, null, 2));

      expect(() => validateConfigFile(configPath)).not.toThrow();
    });
  });

  describe('Deep merge behavior', () => {
    it('should deep merge nested objects', () => {
      const customConfig = {
        detectors: {
          'destructive-commands': {
            safePaths: ['./custom'],
          },
        },
      };

      fs.writeFileSync(
        path.join(testDir, 'noexec.config.json'),
        JSON.stringify(customConfig, null, 2)
      );

      const config = loadConfig();
      expect(config.detectors['destructive-commands'].safePaths).toEqual(['./custom']);
      expect(config.detectors['destructive-commands'].enabled).toBe(true);
      expect(config.detectors['destructive-commands'].severity).toBe('high');
    });

    it('should replace arrays instead of merging them', () => {
      const customConfig = {
        detectors: {
          'git-force-operations': {
            protectedBranches: ['only-this-branch'],
          },
        },
      };

      fs.writeFileSync(
        path.join(testDir, 'noexec.config.json'),
        JSON.stringify(customConfig, null, 2)
      );

      const config = loadConfig();
      expect(config.detectors['git-force-operations'].protectedBranches).toEqual([
        'only-this-branch',
      ]);
      expect(config.detectors['git-force-operations'].protectedBranches).not.toContain('main');
    });
  });
});
