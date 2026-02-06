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

export interface ProcessManipulationConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface BinaryDownloadExecuteConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  trustedDomains?: string[];
}

export interface PackagePoisoningConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface NetworkExfiltrationConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  trustedDomains?: string[];
}

export interface BackdoorPersistenceConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface CredentialHarvestingConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface CodeInjectionConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
}

export interface ContainerEscapeConfig {
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
  'process-manipulation': ProcessManipulationConfig;
  'binary-download-execute': BinaryDownloadExecuteConfig;
  'package-poisoning': PackagePoisoningConfig;
  'network-exfiltration': NetworkExfiltrationConfig;
  'backdoor-persistence': BackdoorPersistenceConfig;
  'credential-harvesting': CredentialHarvestingConfig;
  'code-injection': CodeInjectionConfig;
  'container-escape': ContainerEscapeConfig;
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
