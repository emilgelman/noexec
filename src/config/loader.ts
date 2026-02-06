import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { NoExecConfig } from './types';
import { DEFAULT_CONFIG } from './defaults';
import { validateConfig, ConfigValidationError } from './validator';

/**
 * Deep merge two objects, with source overriding target
 */
function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target };

  for (const key in source) {
    const sourceValue = source[key];
    const targetValue = result[key];

    if (sourceValue === undefined) {
      continue;
    }

    if (
      typeof sourceValue === 'object' &&
      sourceValue !== null &&
      !Array.isArray(sourceValue) &&
      typeof targetValue === 'object' &&
      targetValue !== null &&
      !Array.isArray(targetValue)
    ) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      ) as T[Extract<keyof T, string>];
    } else {
      result[key] = sourceValue as T[Extract<keyof T, string>];
    }
  }

  return result;
}

/**
 * Load config from a file path
 */
function loadConfigFromFile(filePath: string): Partial<NoExecConfig> | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content);
    return parsed as Partial<NoExecConfig>;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new ConfigValidationError(`Invalid JSON in config file: ${filePath}`);
    }
    throw error;
  }
}

/**
 * Find config file paths in priority order
 */
function getConfigPaths(customPath?: string): string[] {
  const paths: string[] = [];

  // 1. Custom path (highest priority)
  if (customPath) {
    paths.push(path.resolve(customPath));
  }

  // 2. Project root (./noexec.config.json)
  paths.push(path.join(process.cwd(), 'noexec.config.json'));

  // 3. User home directory (~/.noexec/config.json)
  const homeDir = os.homedir();
  paths.push(path.join(homeDir, '.noexec', 'config.json'));

  return paths;
}

/**
 * Load and merge config from multiple sources
 */
export function loadConfig(customPath?: string): NoExecConfig {
  let mergedConfig = { ...DEFAULT_CONFIG };
  const configPaths = getConfigPaths(customPath);

  for (const configPath of configPaths) {
    const userConfig = loadConfigFromFile(configPath);
    if (userConfig) {
      // Found a config file, merge it
      mergedConfig = deepMerge(mergedConfig, userConfig);
      break; // Only use the first config file found
    }
  }

  // Validate the final merged config
  validateConfig(mergedConfig);

  return mergedConfig;
}

/**
 * Generate a config file with defaults
 */
export function generateConfigFile(outputPath?: string): string {
  const targetPath = outputPath ?? path.join(process.cwd(), 'noexec.config.json');

  if (fs.existsSync(targetPath)) {
    throw new Error(`Config file already exists at: ${targetPath}`);
  }

  const configJson = JSON.stringify(DEFAULT_CONFIG, null, 2);
  fs.writeFileSync(targetPath, configJson, 'utf-8');

  return targetPath;
}

/**
 * Validate a config file without loading it into the system
 */
export function validateConfigFile(filePath: string): void {
  const configPath = path.resolve(filePath);

  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  const userConfig = loadConfigFromFile(configPath);
  if (!userConfig) {
    throw new Error(`Failed to load config file: ${configPath}`);
  }

  // Merge with defaults to get a complete config for validation
  const mergedConfig = deepMerge(DEFAULT_CONFIG, userConfig);
  validateConfig(mergedConfig);
}
