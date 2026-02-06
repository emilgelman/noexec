import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { PlatformConfig } from './types';

/**
 * Get the path to the user's platform config file
 */
export function getPlatformConfigPath(): string {
  const homeDir = os.homedir();
  return path.join(homeDir, '.noexec', 'config.json');
}

/**
 * Ensure the .noexec directory exists
 */
function ensureConfigDir(): void {
  const homeDir = os.homedir();
  const configDir = path.join(homeDir, '.noexec');

  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
}

/**
 * Load platform config from user's home directory
 */
export function loadPlatformConfig(): PlatformConfig | null {
  const configPath = getPlatformConfigPath();

  if (!fs.existsSync(configPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const config: { platform?: PlatformConfig } = JSON.parse(content);
    return config.platform ?? null;
  } catch {
    // If there's an error reading/parsing, return null
    return null;
  }
}

/**
 * Save platform config to user's home directory
 */
export function savePlatformConfig(platformConfig: PlatformConfig): void {
  ensureConfigDir();
  const configPath = getPlatformConfigPath();

  let existingConfig: Record<string, unknown> = {};

  // Try to preserve existing config
  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      existingConfig = JSON.parse(content) as Record<string, unknown>;
    } catch {
      // If we can't read existing config, start fresh
      existingConfig = {};
    }
  }

  // Merge platform config
  existingConfig.platform = platformConfig;

  // Write back
  fs.writeFileSync(configPath, JSON.stringify(existingConfig, null, 2), 'utf-8');
}

/**
 * Update specific platform config fields
 */
export function updatePlatformConfig(updates: Partial<PlatformConfig>): void {
  const currentConfig = loadPlatformConfig();
  const newConfig: PlatformConfig = {
    enabled: updates.enabled ?? currentConfig?.enabled ?? false,
    apiUrl: updates.apiUrl ?? currentConfig?.apiUrl ?? 'https://platform.noexec.io/api',
    apiKey: updates.apiKey ?? currentConfig?.apiKey ?? '',
    teamId: updates.teamId ?? currentConfig?.teamId ?? '',
  };

  savePlatformConfig(newConfig);
}

/**
 * Check if platform is configured and enabled
 */
export function isPlatformEnabled(): boolean {
  const config = loadPlatformConfig();
  return config?.enabled === true && !!config.apiKey && !!config.teamId;
}
