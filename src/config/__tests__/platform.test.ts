import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  loadPlatformConfig,
  savePlatformConfig,
  updatePlatformConfig,
  isPlatformEnabled,
  getPlatformConfigPath,
} from '../platform';

describe('Platform Config', () => {
  let tempConfigPath: string;
  let originalHome: string;

  beforeEach(() => {
    // Create a temp directory for testing
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'noexec-test-'));
    originalHome = process.env.HOME || os.homedir();
    process.env.HOME = tempDir;
    tempConfigPath = path.join(tempDir, '.noexec', 'config.json');
  });

  afterEach(() => {
    // Clean up
    process.env.HOME = originalHome;
  });

  describe('loadPlatformConfig', () => {
    it('should return null if config does not exist', () => {
      const config = loadPlatformConfig();
      expect(config).toBeNull();
    });

    it('should load platform config from file', () => {
      const testConfig = {
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key_123',
        teamId: 'team_456',
      };

      savePlatformConfig(testConfig);
      const loaded = loadPlatformConfig();

      expect(loaded).toEqual(testConfig);
    });

    it('should return null if file is corrupted', () => {
      fs.mkdirSync(path.dirname(tempConfigPath), { recursive: true });
      fs.writeFileSync(tempConfigPath, 'invalid json{', 'utf-8');

      const config = loadPlatformConfig();
      expect(config).toBeNull();
    });
  });

  describe('savePlatformConfig', () => {
    it('should create config directory if it does not exist', () => {
      const testConfig = {
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key_123',
        teamId: 'team_456',
      };

      savePlatformConfig(testConfig);

      expect(fs.existsSync(tempConfigPath)).toBe(true);
    });

    it('should save platform config correctly', () => {
      const testConfig = {
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key_123',
        teamId: 'team_456',
      };

      savePlatformConfig(testConfig);

      const fileContent = fs.readFileSync(tempConfigPath, 'utf-8');
      const parsed = JSON.parse(fileContent);

      expect(parsed.platform).toEqual(testConfig);
    });

    it('should preserve existing config when updating', () => {
      // Create initial config with extra fields
      fs.mkdirSync(path.dirname(tempConfigPath), { recursive: true });
      fs.writeFileSync(
        tempConfigPath,
        JSON.stringify({ detectors: { foo: 'bar' } }, null, 2),
        'utf-8'
      );

      const testConfig = {
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key_123',
        teamId: 'team_456',
      };

      savePlatformConfig(testConfig);

      const fileContent = fs.readFileSync(tempConfigPath, 'utf-8');
      const parsed = JSON.parse(fileContent);

      expect(parsed.platform).toEqual(testConfig);
      expect(parsed.detectors).toEqual({ foo: 'bar' });
    });
  });

  describe('updatePlatformConfig', () => {
    it('should create new config if none exists', () => {
      updatePlatformConfig({
        enabled: true,
        apiKey: 'new_key',
      });

      const loaded = loadPlatformConfig();
      expect(loaded).toMatchObject({
        enabled: true,
        apiKey: 'new_key',
      });
    });

    it('should update existing config partially', () => {
      savePlatformConfig({
        enabled: false,
        apiUrl: 'https://old.example.com/api',
        apiKey: 'old_key',
        teamId: 'old_team',
      });

      updatePlatformConfig({
        enabled: true,
        apiKey: 'new_key',
      });

      const loaded = loadPlatformConfig();
      expect(loaded).toEqual({
        enabled: true,
        apiUrl: 'https://old.example.com/api',
        apiKey: 'new_key',
        teamId: 'old_team',
      });
    });
  });

  describe('isPlatformEnabled', () => {
    it('should return false if config does not exist', () => {
      expect(isPlatformEnabled()).toBe(false);
    });

    it('should return false if platform is disabled', () => {
      savePlatformConfig({
        enabled: false,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key',
        teamId: 'test_team',
      });

      expect(isPlatformEnabled()).toBe(false);
    });

    it('should return false if apiKey is missing', () => {
      savePlatformConfig({
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: '',
        teamId: 'test_team',
      });

      expect(isPlatformEnabled()).toBe(false);
    });

    it('should return false if teamId is missing', () => {
      savePlatformConfig({
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key',
        teamId: '',
      });

      expect(isPlatformEnabled()).toBe(false);
    });

    it('should return true if platform is properly configured', () => {
      savePlatformConfig({
        enabled: true,
        apiUrl: 'https://test.example.com/api',
        apiKey: 'test_key',
        teamId: 'test_team',
      });

      expect(isPlatformEnabled()).toBe(true);
    });
  });

  describe('getPlatformConfigPath', () => {
    it('should return correct path', () => {
      const expected = path.join(process.env.HOME || os.homedir(), '.noexec', 'config.json');
      expect(getPlatformConfigPath()).toBe(expected);
    });
  });
});
