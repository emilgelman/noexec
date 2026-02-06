import type { NoExecConfig } from './types';

export const DEFAULT_CONFIG: NoExecConfig = {
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
      safePaths: ['./node_modules', './dist', './build', './target', './out', './coverage'],
      additionalPatterns: [],
    },
    'git-force-operations': {
      enabled: true,
      severity: 'high',
      protectedBranches: ['main', 'master', 'production', 'prod', 'release'],
      allowForceWithLease: true,
    },
    'env-var-leak': {
      enabled: true,
      severity: 'high',
      sensitiveVars: [
        'API_KEY',
        'SECRET',
        'PASSWORD',
        'TOKEN',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'DATABASE_URL',
        'PRIVATE_KEY',
      ],
    },
    'magic-string': {
      enabled: true,
      severity: 'high',
    },
    'binary-download-execute': {
      enabled: true,
      severity: 'high',
      trustedDomains: [],
    },
    'package-poisoning': {
      enabled: true,
      severity: 'high',
    },
    'security-tool-disabling': {
      enabled: true,
      severity: 'high',
    },
    'network-exfiltration': {
      enabled: true,
      severity: 'high',
      trustedDomains: [],
    },
    'backdoor-persistence': {
      enabled: true,
      severity: 'high',
    },
    'credential-harvesting': {
      enabled: true,
      severity: 'high',
    },
    'code-injection': {
      enabled: true,
      severity: 'high',
    },
    'container-escape': {
      enabled: true,
      severity: 'high',
    },
    'archive-bomb': {
      enabled: true,
      severity: 'high',
    },
    'process-manipulation': {
      enabled: true,
      severity: 'high',
    },
  },
  globalSettings: {
    minSeverity: 'medium',
    exitOnDetection: true,
    jsonOutput: false,
  },
  platform: {
    enabled: false,
    apiUrl: 'https://platform.noexec.io/api',
    apiKey: '',
    teamId: '',
  },
};
