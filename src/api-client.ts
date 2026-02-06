import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
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
