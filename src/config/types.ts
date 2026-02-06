export interface CredentialLeakConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  customPatterns: string[];
  minEntropy: number;
  ignorePlaceholders: boolean;
}

export interface DestructiveCommandsConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  safePaths: string[];
  additionalPatterns: string[];
}

export interface GitForceOperationsConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  protectedBranches: string[];
  allowForceWithLease: boolean;
}

export interface EnvVarLeakConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  sensitiveVars: string[];
}

export interface MagicStringConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface SecurityToolDisablingConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface ArchiveBombConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface DetectorsConfig {
  'credential-leak': CredentialLeakConfig;
  'destructive-commands': DestructiveCommandsConfig;
  'git-force-operations': GitForceOperationsConfig;
  'env-var-leak': EnvVarLeakConfig;
  'magic-string': MagicStringConfig;
  'security-tool-disabling': SecurityToolDisablingConfig;
  'archive-bomb': ArchiveBombConfig;
}

export interface GlobalSettings {
  minSeverity: 'high' | 'medium' | 'low';
  exitOnDetection: boolean;
  jsonOutput: boolean;
}

export interface NoExecConfig {
  detectors: DetectorsConfig;
  globalSettings: GlobalSettings;
}
