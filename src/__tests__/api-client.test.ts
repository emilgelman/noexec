import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fetchTeamConfigCached } from '../api-client';

// Mock modules
vi.mock('../config/platform', () => ({
  loadPlatformConfig: vi.fn(),
}));

describe('fetchTeamConfigCached', () => {
  const mockCachePath = path.join(os.homedir(), '.noexec', 'cache', 'team-config.json');

  beforeEach(() => {
    // Clean up cache before each test
    if (fs.existsSync(mockCachePath)) {
      fs.unlinkSync(mockCachePath);
    }
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('should return null if user is not authenticated', async () => {
    const { loadPlatformConfig } = await import('../config/platform');
    vi.mocked(loadPlatformConfig).mockReturnValue(null);

    const result = await fetchTeamConfigCached();
    expect(result).toBeNull();
  });

  it('should return null if platform config is missing apiKey', async () => {
    const { loadPlatformConfig } = await import('../config/platform');
    vi.mocked(loadPlatformConfig).mockReturnValue({
      enabled: true,
      apiUrl: 'https://test.com',
      apiKey: '',
      teamId: 'team-123',
    });

    const result = await fetchTeamConfigCached();
    expect(result).toBeNull();
  });

  it('should return null if platform config is missing teamId', async () => {
    const { loadPlatformConfig } = await import('../config/platform');
    vi.mocked(loadPlatformConfig).mockReturnValue({
      enabled: true,
      apiUrl: 'https://test.com',
      apiKey: 'key-123',
      teamId: '',
    });

    const result = await fetchTeamConfigCached();
    expect(result).toBeNull();
  });

  it('should return cached data if cache is fresh (< 1 hour)', async () => {
    const { loadPlatformConfig } = await import('../config/platform');
    vi.mocked(loadPlatformConfig).mockReturnValue({
      enabled: true,
      apiUrl: 'https://test.com',
      apiKey: 'key-123',
      teamId: 'team-123',
    });

    // Create fresh cache (30 minutes ago)
    const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;
    const cachedData = {
      data: {
        teamId: 'team-123',
        teamName: 'Test Team',
        config: { detectors: { 'credential-leak': { enabled: true } } },
      },
      timestamp: thirtyMinutesAgo,
    };

    const cacheDir = path.dirname(mockCachePath);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.writeFileSync(mockCachePath, JSON.stringify(cachedData));

    const result = await fetchTeamConfigCached();
    expect(result).toEqual(cachedData.data);
  });

  it('should ignore corrupted cache and return null on API failure', async () => {
    const { loadPlatformConfig } = await import('../config/platform');
    vi.mocked(loadPlatformConfig).mockReturnValue({
      enabled: true,
      apiUrl: 'https://test.com',
      apiKey: 'key-123',
      teamId: 'team-123',
    });

    // Create corrupted cache
    const cacheDir = path.dirname(mockCachePath);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.writeFileSync(mockCachePath, 'invalid json{]');

    const result = await fetchTeamConfigCached();
    // Should fail silently and return null (since API will also fail in test env)
    expect(result).toBeNull();
  });
});
