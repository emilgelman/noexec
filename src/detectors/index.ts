export type { Detection, Detector, ToolUseData } from '../types';

export { detectCredentialLeak } from './credential-leak';
export { detectDestructiveCommand } from './destructive-commands';
export { detectGitForceOperations } from './git-force-operations';
export { detectEnvVarLeak } from './env-var-leak';
export { detectNetworkExfiltration } from './network-exfiltration';
export { detectMagicString } from './magic-string';
export { detectPackagePoisoning } from './package-poisoning';
export { detectBinaryDownloadExecute } from './binary-download-execute';
export { detectSecurityToolDisabling } from './security-tool-disabling';
export { detectCodeInjection } from './code-injection';
