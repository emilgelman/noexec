import * as fs from 'fs';
import chalk from 'chalk';
import type { Detection, ToolUseData } from '../types';
import { detectCredentialLeak } from '../detectors/credential-leak';
import { detectMagicString } from '../detectors/magic-string';
import { detectDestructiveCommand } from '../detectors/destructive-commands';
import { detectGitForceOperation } from '../detectors/git-force-operations';
import { detectEnvVarLeak } from '../detectors/env-var-leak';
import { detectSecurityToolDisabling } from '../detectors/security-tool-disabling';
import { detectBinaryDownloadExecute } from '../detectors/binary-download-execute';
import { detectPackagePoisoning } from '../detectors/package-poisoning';
import { detectNetworkExfiltration } from '../detectors/network-exfiltration';
import { detectBackdoorPersistence } from '../detectors/backdoor-persistence';
import { detectCredentialHarvesting } from '../detectors/credential-harvesting';
import { detectCodeInjection } from '../detectors/code-injection';
import { detectContainerEscape } from '../detectors/container-escape';
import { detectArchiveBomb } from '../detectors/archive-bomb';
import { detectProcessManipulation } from '../detectors/process-manipulation';
import { loadConfig, type NoExecConfig } from '../config';

interface AnalyzeOptions {
  hook: string;
  config?: string;
}

/**
 * Get color and icon for severity level
 */
function formatSeverity(severity: string): string {
  switch (severity) {
    case 'high':
      return chalk.red.bold('🚨 HIGH');
    case 'medium':
      return chalk.yellow.bold('⚠️  MEDIUM');
    case 'low':
      return chalk.blue.bold('ℹ️  LOW');
    default:
      return chalk.gray.bold(`❓ ${severity.toUpperCase()}`);
  }
}

/**
 * Get helpful suggestion based on detector type
 */
function getSuggestion(detector: string): string | null {
  const suggestions: Record<string, string> = {
    'git-force-operation':
      'Consider using --force-with-lease instead of --force for safer force-pushing.',
    'destructive-command':
      'Review the command carefully. Consider using trash/mv for safer file deletion.',
    'credential-leak':
      'Never hardcode credentials. Use environment variables or secret managers instead.',
    'env-var-leak': 'Avoid exporting sensitive variables. Consider using .env files or vaults.',
    'magic-string':
      'Hardcoded sensitive data detected. Use configuration files or environment variables.',
    'binary-download-execute':
      'Avoid piping downloaded content directly to shell. Review and save scripts before executing.',
    'package-poisoning':
      'Verify package integrity. Use official package managers and check package signatures.',
    'security-tool-disabling':
      'Disabling security tools is dangerous. Reconsider if this is necessary.',
    'network-exfiltration':
      'Suspicious data exfiltration detected. Verify the destination and data being sent.',
    'backdoor-persistence':
      'Persistence mechanism detected. Ensure this is intentional and authorized.',
    'credential-harvesting':
      'Credential access detected. Use secure credential management systems.',
    'code-injection': 'Code injection technique detected. Review for security implications.',
    'container-escape':
      'Container escape attempt detected. Review privileged operations carefully.',
    'archive-bomb': 'Zip bomb or archive bomb detected. Decompress with limits and monitoring.',
    'process-manipulation':
      'Process manipulation detected. Ensure debugging/profiling is intentional.',
  };
  return suggestions[detector] || null;
}

function shouldReportDetection(detection: Detection, config: NoExecConfig): boolean {
  const severityOrder = { low: 0, medium: 1, high: 2 };
  const minSeverityLevel = severityOrder[config.globalSettings.minSeverity];
  const detectionLevel = severityOrder[detection.severity];

  return detectionLevel >= minSeverityLevel;
}

export async function analyzeStdin(input: string, config?: NoExecConfig): Promise<Detection[]> {
  if (!input.trim()) {
    return [];
  }

  let toolUseData: ToolUseData;
  try {
    toolUseData = JSON.parse(input) as ToolUseData;
  } catch (error) {
    throw new Error(
      `Invalid JSON input: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const activeConfig = config ?? loadConfig();

  const detectors = [
    {
      fn: detectDestructiveCommand,
      config: activeConfig.detectors['destructive-commands'],
    },
    {
      fn: detectGitForceOperation,
      config: activeConfig.detectors['git-force-operations'],
    },
    {
      fn: detectCredentialLeak,
      config: activeConfig.detectors['credential-leak'],
    },
    {
      fn: detectEnvVarLeak,
      config: activeConfig.detectors['env-var-leak'],
    },
    {
      fn: detectMagicString,
      config: activeConfig.detectors['magic-string'],
    },
    {
      fn: detectBinaryDownloadExecute,
      config: activeConfig.detectors['binary-download-execute'],
    },
    {
      fn: detectPackagePoisoning,
      config: activeConfig.detectors['package-poisoning'],
    },
    {
      fn: detectSecurityToolDisabling,
      config: activeConfig.detectors['security-tool-disabling'],
    },
    {
      fn: detectNetworkExfiltration,
      config: activeConfig.detectors['network-exfiltration'],
    },
    {
      fn: detectBackdoorPersistence,
      config: activeConfig.detectors['backdoor-persistence'],
    },
    {
      fn: detectCredentialHarvesting,
      config: activeConfig.detectors['credential-harvesting'],
    },
    {
      fn: detectCodeInjection,
      config: activeConfig.detectors['code-injection'],
    },
    {
      fn: detectContainerEscape,
      config: activeConfig.detectors['container-escape'],
    },
    {
      fn: detectArchiveBomb,
      config: activeConfig.detectors['archive-bomb'],
    },
    {
      fn: detectProcessManipulation,
      config: activeConfig.detectors['process-manipulation'],
    },
  ];

  const detections: Detection[] = [];

  for (const detector of detectors) {
    const result = await detector.fn(toolUseData, detector.config as never);
    if (result && shouldReportDetection(result, activeConfig)) {
      detections.push(result);
    }
  }

  return detections;
}

export async function analyzeCommand(options: AnalyzeOptions): Promise<void> {
  try {
    const config = loadConfig(options.config);
    const stdin = fs.readFileSync(0, 'utf-8');
    const detections = await analyzeStdin(stdin, config);

    if (detections.length > 0) {
      if (config.globalSettings.jsonOutput) {
        console.log(JSON.stringify({ detections }, null, 2));
      } else {
        console.error(chalk.red.bold('\n🛡️  Security Issues Detected\n'));
        console.error(chalk.gray('─'.repeat(60)) + '\n');

        for (const detection of detections) {
          console.error(formatSeverity(detection.severity) + ' ' + chalk.white(detection.message));
          console.error(chalk.gray(`   Detector: ${detection.detector}`));

          const suggestion = getSuggestion(detection.detector);
          if (suggestion) {
            console.error(chalk.cyan(`   💡 Tip: ${suggestion}`));
          }
          console.error('');
        }

        console.error(chalk.gray('─'.repeat(60)));
        console.error(
          chalk.yellow(
            `\n⚡ Found ${detections.length} security ${detections.length === 1 ? 'issue' : 'issues'}. Review before proceeding.\n`
          )
        );
      }

      if (config.globalSettings.exitOnDetection) {
        process.exit(2);
      }
    }

    // Success - no issues detected
    process.exit(0);
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Error: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ An unexpected error occurred\n'));
    }
    // Exit 0 on error to not block the tool (fail-open for safety)
    process.exit(0);
  }
}
