export type { Detection, Detector, ToolUseData } from '../types';

// Original detectors (5)
export { detectCredentialLeak } from './credential-leak';
export { detectDestructiveCommand } from './destructive-commands';
export { detectGitForceOperations } from './git-force-operations';
export { detectEnvVarLeak } from './env-var-leak';
export { detectMagicString } from './magic-string';

// New detectors (10)
export { detectBinaryDownloadExecute } from './binary-download-execute';
export { detectPackagePoisoning } from './package-poisoning';
export { detectSecurityToolDisabling } from './security-tool-disabling';
export { detectNetworkExfiltration } from './network-exfiltration';
export { detectBackdoorPersistence } from './backdoor-persistence';
export { detectCredentialHarvesting } from './credential-harvesting';
export { detectCodeInjection } from './code-injection';
export { detectContainerEscape } from './container-escape';
export { detectArchiveBomb } from './archive-bomb';
export { detectProcessManipulation } from './process-manipulation';
