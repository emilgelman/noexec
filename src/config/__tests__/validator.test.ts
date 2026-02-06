import { describe, it, expect } from 'vitest';
import { validateConfig, ConfigValidationError, type NoExecConfig } from '../validator';

describe('Config Validator', () => {
  describe('Valid configurations', () => {
    it('should accept a complete valid config', () => {
      const config: NoExecConfig = {
        detectors: {
          'credential-leak': {
            enabled: true,
            severity: 'high',
            customPatterns: [],
            minEntropy: 3.0,
            ignorePlaceholders: true,
          },
          'destructive-commands': {
            enabled: true,
            severity: 'high',
            safePaths: ['./node_modules'],
            additionalPatterns: [],
          },
          'git-force-operations': {
            enabled: true,
            severity: 'high',
            protectedBranches: ['main'],
            allowForceWithLease: true,
          },
          'env-var-leak': {
            enabled: true,
            severity: 'high',
            sensitiveVars: ['API_KEY'],
          },
          'magic-string': {
            enabled: true,
            severity: 'high',
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should accept partial detector configuration', () => {
      const config = {
        detectors: {
          'credential-leak': {
            enabled: true,
            severity: 'high',
            customPatterns: [],
            minEntropy: 3.0,
            ignorePlaceholders: true,
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should accept all severity levels', () => {
      for (const severity of ['low', 'medium', 'high']) {
        const config = {
          detectors: {
            'magic-string': {
              enabled: true,
              severity: severity as 'low' | 'medium' | 'high',
            },
          },
          globalSettings: {
            minSeverity: severity as 'low' | 'medium' | 'high',
            exitOnDetection: true,
            jsonOutput: false,
          },
        };

        expect(() => validateConfig(config)).not.toThrow();
      }
    });
  });

  describe('Invalid configurations', () => {
    it('should reject non-object config', () => {
      expect(() => validateConfig(null)).toThrow(ConfigValidationError);
      expect(() => validateConfig('string')).toThrow(ConfigValidationError);
      expect(() => validateConfig([])).toThrow(ConfigValidationError);
    });

    it('should reject config missing detectors', () => {
      const config = {
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
      expect(() => validateConfig(config)).toThrow(/detectors/);
    });

    it('should reject config missing globalSettings', () => {
      const config = {
        detectors: {},
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
      expect(() => validateConfig(config)).toThrow(/globalSettings/);
    });

    it('should reject invalid severity levels', () => {
      const config = {
        detectors: {
          'magic-string': {
            enabled: true,
            severity: 'critical', // Invalid
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });

    it('should reject unknown detector names', () => {
      const config = {
        detectors: {
          'unknown-detector': {
            enabled: true,
            severity: 'high',
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
      expect(() => validateConfig(config)).toThrow(/Unknown detector/);
    });

    it('should reject detector with non-boolean enabled', () => {
      const config = {
        detectors: {
          'magic-string': {
            enabled: 'yes', // Should be boolean
            severity: 'high',
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });
  });

  describe('Detector-specific validation', () => {
    it('should validate credential-leak config', () => {
      const config = {
        detectors: {
          'credential-leak': {
            enabled: true,
            severity: 'high',
            customPatterns: ['pattern1'],
            minEntropy: 3.5,
            ignorePlaceholders: false,
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should reject credential-leak with invalid minEntropy', () => {
      const config = {
        detectors: {
          'credential-leak': {
            enabled: true,
            severity: 'high',
            customPatterns: [],
            minEntropy: -1, // Invalid
            ignorePlaceholders: true,
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });

    it('should reject credential-leak with non-array customPatterns', () => {
      const config = {
        detectors: {
          'credential-leak': {
            enabled: true,
            severity: 'high',
            customPatterns: 'not-an-array',
            minEntropy: 3.0,
            ignorePlaceholders: true,
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });

    it('should validate destructive-commands config', () => {
      const config = {
        detectors: {
          'destructive-commands': {
            enabled: true,
            severity: 'high',
            safePaths: ['./node_modules', './dist'],
            additionalPatterns: ['\\brm\\b'],
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should validate git-force-operations config', () => {
      const config = {
        detectors: {
          'git-force-operations': {
            enabled: true,
            severity: 'high',
            protectedBranches: ['main', 'master', 'develop'],
            allowForceWithLease: false,
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should validate env-var-leak config', () => {
      const config = {
        detectors: {
          'env-var-leak': {
            enabled: true,
            severity: 'high',
            sensitiveVars: ['MY_SECRET', 'API_TOKEN'],
          },
        },
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).not.toThrow();
    });
  });

  describe('GlobalSettings validation', () => {
    it('should reject invalid minSeverity', () => {
      const config = {
        detectors: {},
        globalSettings: {
          minSeverity: 'invalid',
          exitOnDetection: true,
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });

    it('should reject non-boolean exitOnDetection', () => {
      const config = {
        detectors: {},
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: 'yes',
          jsonOutput: false,
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });

    it('should reject non-boolean jsonOutput', () => {
      const config = {
        detectors: {},
        globalSettings: {
          minSeverity: 'medium',
          exitOnDetection: true,
          jsonOutput: 'yes',
        },
      };

      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
    });
  });
});
