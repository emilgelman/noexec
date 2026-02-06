import * as fs from 'fs';
import type { Detection, ToolUseData } from '../types';
import { detectCredentialLeak } from '../detectors/credential-leak';
import { detectMagicString } from '../detectors/magic-string';
import { detectDestructiveCommand } from '../detectors/destructive-commands';
import { detectGitForceOperation } from '../detectors/git-force-operations';
import { detectEnvVarLeak } from '../detectors/env-var-leak';

interface AnalyzeOptions {
  hook: string;
}

export async function analyzeStdin(input: string): Promise<Detection[]> {
  if (!input.trim()) {
    return [];
  }

  const toolUseData = JSON.parse(input) as ToolUseData;

  const detectors = [
    detectDestructiveCommand,
    detectGitForceOperation,
    detectCredentialLeak,
    detectEnvVarLeak,
    detectMagicString,
  ];

  const detections: Detection[] = [];

  for (const detector of detectors) {
    const result = await detector(toolUseData);
    if (result) {
      detections.push(result);
    }
  }

  return detections;
}

export async function analyzeCommand(_options: AnalyzeOptions): Promise<void> {
  try {
    const stdin = fs.readFileSync(0, 'utf-8');
    const detections = await analyzeStdin(stdin);

    if (detections.length > 0) {
      console.error('\n⚠️  Security issues detected:\n');
      for (const detection of detections) {
        console.error(`[${detection.severity.toUpperCase()}] ${detection.message}`);
        console.error(`  Detector: ${detection.detector}\n`);
      }
      process.exit(2);
    }

    process.exit(0);
  } catch (error) {
    console.error('Error analyzing tool use:', error);
    process.exit(0);
  }
}
