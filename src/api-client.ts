import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { Detection } from './types';
import type { PlatformConfig } from './config/types';
import { loadPlatformConfig } from './config/platform';

export interface BlockEventPayload {
  timestamp: string;
  severity: 'high' | 'medium' | 'low';
  detector: string;
  message: string;
  command_hash: string;
  metadata: {
    cli_version: string;
    platform: string;
  };
}

export interface TeamConfigResponse {
  teamId: string;
  teamName: string;
  config?: Record<string, unknown>;
}

interface CachedTeamConfig {
  data: TeamConfigResponse;
  timestamp: number;
}

export interface LoginResponse {
  apiKey: string;
  teamId: string;
  teamName: string;
}

/**
 * Hash a command for privacy (never send raw commands to platform)
 */
function hashCommand(command: string): string {
  return crypto.createHash('sha256').update(command).digest('hex');
}

/**
 * Make an HTTP/HTTPS request
 */
function makeRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body?: string
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port ?? (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };

    const req = client.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          body: data,
        });
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (body) {
      req.write(body);
    }

    req.end();
  });
}

/**
 * Report a security detection to the platform
 */
export async function reportDetection(
  detection: Detection,
  command: string,
  platform = 'claude'
): Promise<void> {
  const config = loadPlatformConfig();

  if (!config || !config.enabled || !config.apiKey || !config.teamId) {
    // Platform not configured or disabled - skip silently
    return;
  }

  const payload: BlockEventPayload = {
    timestamp: new Date().toISOString(),
    severity: detection.severity,
    detector: detection.detector,
    message: detection.message,
    command_hash: hashCommand(command),
    metadata: {
      cli_version: '1.0.0', // TODO: Pull from package.json
      platform,
    },
  };

  try {
    const response = await makeRequest(
      `${config.apiUrl}/v1/blocks`,
      'POST',
      {
        Authorization: `Bearer ${config.apiKey}`,
        'X-Team-ID': config.teamId,
      },
      JSON.stringify(payload)
    );

    if (response.statusCode >= 400) {
      // Silent failure - don't block the CLI if platform is down
      console.error(`Warning: Failed to report detection to platform (${response.statusCode})`);
    }
  } catch (error) {
    // Silent failure - network issues shouldn't block the CLI
    if (error instanceof Error) {
      console.error(`Warning: Could not reach platform: ${error.message}`);
    }
  }
}

/**
 * Authenticate with the platform and get API key
 */
export async function login(
  email: string,
  password: string,
  apiUrl?: string
): Promise<LoginResponse> {
  const baseUrl = apiUrl ?? 'https://platform.noexec.io/api';

  const payload = {
    email,
    password,
  };

  const response = await makeRequest(
    `${baseUrl}/v1/auth/login`,
    'POST',
    {},
    JSON.stringify(payload)
  );

  if (response.statusCode !== 200) {
    throw new Error(`Login failed: ${response.body || 'Unknown error'}`);
  }

  const data = JSON.parse(response.body) as LoginResponse;

  if (!data.apiKey || !data.teamId) {
    throw new Error('Invalid login response from platform');
  }

  return data;
}

/**
 * Fetch team configuration from the platform
 */
export async function fetchTeamConfig(config: PlatformConfig): Promise<TeamConfigResponse> {
  const response = await makeRequest(`${config.apiUrl}/v1/teams/${config.teamId}/config`, 'GET', {
    Authorization: `Bearer ${config.apiKey}`,
  });

  if (response.statusCode !== 200) {
    throw new Error(`Failed to fetch team config: ${response.body || 'Unknown error'}`);
  }

  return JSON.parse(response.body) as TeamConfigResponse;
}

/**
 * Get the path to the team config cache file
 */
function getTeamConfigCachePath(): string {
  const homeDir = os.homedir();
  return path.join(homeDir, '.noexec', 'cache', 'team-config.json');
}

/**
 * Ensure the cache directory exists
 */
function ensureCacheDir(): void {
  const homeDir = os.homedir();
  const cacheDir = path.join(homeDir, '.noexec', 'cache');

  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
}

/**
 * Fetch team configuration with 1-hour file-based cache
 * Returns null if user is not authenticated or on any error (silent failure)
 */
export async function fetchTeamConfigCached(): Promise<TeamConfigResponse | null> {
  try {
    const platformConfig = loadPlatformConfig();

    // If not authenticated, return null silently
    if (!platformConfig?.apiKey || !platformConfig.teamId) {
      return null;
    }

    const cachePath = getTeamConfigCachePath();
    const ONE_HOUR = 60 * 60 * 1000; // 1 hour in milliseconds

    // Check if cache exists and is fresh
    if (fs.existsSync(cachePath)) {
      try {
        const cacheContent = fs.readFileSync(cachePath, 'utf-8');
        const cached: CachedTeamConfig = JSON.parse(cacheContent);

        const age = Date.now() - cached.timestamp;
        if (age < ONE_HOUR) {
          // Cache is fresh, return cached data
          return cached.data;
        }
      } catch {
        // If cache is corrupted, continue to fetch fresh data
      }
    }

    // Cache miss or stale - fetch fresh data
    const freshData = await fetchTeamConfig(platformConfig);

    // Save to cache
    try {
      ensureCacheDir();
      const cached: CachedTeamConfig = {
        data: freshData,
        timestamp: Date.now(),
      };
      fs.writeFileSync(cachePath, JSON.stringify(cached, null, 2), 'utf-8');
    } catch {
      // If we can't save cache, that's fine - just continue
    }

    return freshData;
  } catch {
    // Silent failure - if API is unreachable or any error, return null
    return null;
  }
}
