import type { NoExecConfig } from './types';

export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public path?: string
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

const VALID_SEVERITIES = ['high', 'medium', 'low'];
const VALID_DETECTOR_NAMES = [
  'credential-leak',
  'destructive-commands',
  'git-force-operations',
  'env-var-leak',
  'magic-string',
];

function isValidSeverity(value: unknown): value is 'high' | 'medium' | 'low' {
  return typeof value === 'string' && VALID_SEVERITIES.includes(value);
}

function validateCommonDetectorFields(
  detector: unknown,
  detectorName: string,
  requiredFields: string[] = []
): void {
  if (typeof detector !== 'object' || detector === null) {
    throw new ConfigValidationError(
      `Detector ${detectorName} must be an object`,
      `detectors.${detectorName}`
    );
  }

  const det = detector as Record<string, unknown>;

  if (typeof det.enabled !== 'boolean') {
    throw new ConfigValidationError(
      `Detector ${detectorName}.enabled must be a boolean`,
      `detectors.${detectorName}.enabled`
    );
  }

  if (!isValidSeverity(det.severity)) {
    throw new ConfigValidationError(
      `Detector ${detectorName}.severity must be one of: ${VALID_SEVERITIES.join(', ')}`,
      `detectors.${detectorName}.severity`
    );
  }

  for (const field of requiredFields) {
    if (!(field in det)) {
      throw new ConfigValidationError(
        `Detector ${detectorName} is missing required field: ${field}`,
        `detectors.${detectorName}.${field}`
      );
    }
  }
}

function validateCredentialLeakConfig(config: unknown): void {
  validateCommonDetectorFields(config, 'credential-leak', [
    'customPatterns',
    'minEntropy',
    'ignorePlaceholders',
  ]);

  const det = config as Record<string, unknown>;

  if (!Array.isArray(det.customPatterns)) {
    throw new ConfigValidationError(
      'credential-leak.customPatterns must be an array',
      'detectors.credential-leak.customPatterns'
    );
  }

  if (!det.customPatterns.every((p) => typeof p === 'string')) {
    throw new ConfigValidationError(
      'credential-leak.customPatterns must contain only strings',
      'detectors.credential-leak.customPatterns'
    );
  }

  if (typeof det.minEntropy !== 'number' || det.minEntropy < 0) {
    throw new ConfigValidationError(
      'credential-leak.minEntropy must be a non-negative number',
      'detectors.credential-leak.minEntropy'
    );
  }

  if (typeof det.ignorePlaceholders !== 'boolean') {
    throw new ConfigValidationError(
      'credential-leak.ignorePlaceholders must be a boolean',
      'detectors.credential-leak.ignorePlaceholders'
    );
  }
}

function validateDestructiveCommandsConfig(config: unknown): void {
  validateCommonDetectorFields(config, 'destructive-commands', ['safePaths', 'additionalPatterns']);

  const det = config as Record<string, unknown>;

  if (!Array.isArray(det.safePaths)) {
    throw new ConfigValidationError(
      'destructive-commands.safePaths must be an array',
      'detectors.destructive-commands.safePaths'
    );
  }

  if (!det.safePaths.every((p) => typeof p === 'string')) {
    throw new ConfigValidationError(
      'destructive-commands.safePaths must contain only strings',
      'detectors.destructive-commands.safePaths'
    );
  }

  if (!Array.isArray(det.additionalPatterns)) {
    throw new ConfigValidationError(
      'destructive-commands.additionalPatterns must be an array',
      'detectors.destructive-commands.additionalPatterns'
    );
  }

  if (!det.additionalPatterns.every((p) => typeof p === 'string')) {
    throw new ConfigValidationError(
      'destructive-commands.additionalPatterns must contain only strings',
      'detectors.destructive-commands.additionalPatterns'
    );
  }
}

function validateGitForceOperationsConfig(config: unknown): void {
  validateCommonDetectorFields(config, 'git-force-operations', [
    'protectedBranches',
    'allowForceWithLease',
  ]);

  const det = config as Record<string, unknown>;

  if (!Array.isArray(det.protectedBranches)) {
    throw new ConfigValidationError(
      'git-force-operations.protectedBranches must be an array',
      'detectors.git-force-operations.protectedBranches'
    );
  }

  if (!det.protectedBranches.every((b) => typeof b === 'string')) {
    throw new ConfigValidationError(
      'git-force-operations.protectedBranches must contain only strings',
      'detectors.git-force-operations.protectedBranches'
    );
  }

  if (typeof det.allowForceWithLease !== 'boolean') {
    throw new ConfigValidationError(
      'git-force-operations.allowForceWithLease must be a boolean',
      'detectors.git-force-operations.allowForceWithLease'
    );
  }
}

function validateEnvVarLeakConfig(config: unknown): void {
  validateCommonDetectorFields(config, 'env-var-leak', ['sensitiveVars']);

  const det = config as Record<string, unknown>;

  if (!Array.isArray(det.sensitiveVars)) {
    throw new ConfigValidationError(
      'env-var-leak.sensitiveVars must be an array',
      'detectors.env-var-leak.sensitiveVars'
    );
  }

  if (!det.sensitiveVars.every((v) => typeof v === 'string')) {
    throw new ConfigValidationError(
      'env-var-leak.sensitiveVars must contain only strings',
      'detectors.env-var-leak.sensitiveVars'
    );
  }
}

function validateMagicStringConfig(config: unknown): void {
  validateCommonDetectorFields(config, 'magic-string');
}

function validateDetectors(detectors: unknown): void {
  if (typeof detectors !== 'object' || detectors === null) {
    throw new ConfigValidationError('detectors must be an object', 'detectors');
  }

  const det = detectors as Record<string, unknown>;

  // Check for unknown detector names
  for (const key of Object.keys(det)) {
    if (!VALID_DETECTOR_NAMES.includes(key)) {
      throw new ConfigValidationError(
        `Unknown detector: ${key}. Valid detectors: ${VALID_DETECTOR_NAMES.join(', ')}`,
        `detectors.${key}`
      );
    }
  }

  // Validate each detector if present
  if (det['credential-leak']) {
    validateCredentialLeakConfig(det['credential-leak']);
  }

  if (det['destructive-commands']) {
    validateDestructiveCommandsConfig(det['destructive-commands']);
  }

  if (det['git-force-operations']) {
    validateGitForceOperationsConfig(det['git-force-operations']);
  }

  if (det['env-var-leak']) {
    validateEnvVarLeakConfig(det['env-var-leak']);
  }

  if (det['magic-string']) {
    validateMagicStringConfig(det['magic-string']);
  }
}

function validateGlobalSettings(settings: unknown): void {
  if (typeof settings !== 'object' || settings === null) {
    throw new ConfigValidationError('globalSettings must be an object', 'globalSettings');
  }

  const s = settings as Record<string, unknown>;

  if (!isValidSeverity(s.minSeverity)) {
    throw new ConfigValidationError(
      `globalSettings.minSeverity must be one of: ${VALID_SEVERITIES.join(', ')}`,
      'globalSettings.minSeverity'
    );
  }

  if (typeof s.exitOnDetection !== 'boolean') {
    throw new ConfigValidationError(
      'globalSettings.exitOnDetection must be a boolean',
      'globalSettings.exitOnDetection'
    );
  }

  if (typeof s.jsonOutput !== 'boolean') {
    throw new ConfigValidationError(
      'globalSettings.jsonOutput must be a boolean',
      'globalSettings.jsonOutput'
    );
  }
}

export function validateConfig(config: unknown): asserts config is NoExecConfig {
  if (typeof config !== 'object' || config === null) {
    throw new ConfigValidationError('Config must be an object');
  }

  const cfg = config as Record<string, unknown>;

  if (!('detectors' in cfg)) {
    throw new ConfigValidationError('Config must have a "detectors" field');
  }

  if (!('globalSettings' in cfg)) {
    throw new ConfigValidationError('Config must have a "globalSettings" field');
  }

  validateDetectors(cfg.detectors);
  validateGlobalSettings(cfg.globalSettings);
}
